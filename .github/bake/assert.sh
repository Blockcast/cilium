#!/usr/bin/env bash
# BLO-45348 bake assertions: cilium health, pod-to-pod, multicast CEGP SNAT,
# unicast CEGP SNAT. Prints evidence; exits non-zero on the first failed check.
set -euo pipefail

GW=kind-worker2
OTHER=kind-worker
NS=bake
GROUP=232.1.1.1
NETSHOOT=nicolaka/netshoot:v0.13
fail() { echo "ASSERT FAIL: $*"; exit 1; }
ok()   { echo "ASSERT PASS: $*"; }
agent_on() { kubectl -n kube-system get pod -l k8s-app=cilium --field-selector spec.nodeName="$1" -o name; }
dbg() { kubectl -n kube-system exec "$(agent_on "$1")" -c cilium-agent -- "${@:2}"; }

echo "=== 1. image booted ==="
ids=$(kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath='{range .items[*]}{.spec.nodeName} {.status.containerStatuses[?(@.name=="cilium-agent")].imageID}{"\n"}{end}')
echo "$ids"
[ "$(echo "$ids" | grep -c "@${IMAGE_DIGEST}$")" -eq 3 ] || fail "not all 3 agents run ${IMAGE_DIGEST}"
ok "all 3 cilium-agent containers run ${IMAGE_DIGEST}"

echo "=== 2. cilium status ==="
cilium status --wait --wait-duration 5m
for n in kind-control-plane $OTHER $GW; do
  dbg "$n" cilium-dbg status | sed -n '1,40p'
  dbg "$n" cilium-health status --probe --succinct
done
ok "cilium status healthy"

echo "=== 3. workloads ==="
kubectl create ns $NS
GW_MAC=$(docker exec $GW cat /sys/class/net/eth0/address)
mkpod() { # name node label cmd
  kubectl -n $NS run "$1" --image=$NETSHOOT --labels="app=$3" \
    --overrides="{\"spec\":{\"nodeName\":\"$2\"}}" --command -- sh -c "$4"
}
ECHO='socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:"echo \$SOCAT_PEERADDR"'
mkpod src-remote $OTHER egw-src 'sleep infinity'
mkpod src-local  $GW    egw-src 'sleep infinity'
mkpod echo-a     $OTHER echo "$ECHO"
mkpod echo-b     $GW    echo "$ECHO"
kubectl -n $NS wait --for=condition=Ready pod --all --timeout=180s
kubectl -n $NS get pods -o wide
ip_of() { kubectl -n $NS get pod "$1" -o jsonpath='{.status.podIP}'; }

echo "=== 4. pod-to-pod ==="
SRC_IP=$(ip_of src-remote)
for dst in echo-a echo-b; do
  got=$(kubectl -n $NS exec src-remote -- curl -s --max-time 5 "$(ip_of $dst):8080")
  echo "src-remote($SRC_IP) -> $dst: peer=$got"
  [ "$got" = "$SRC_IP" ] || fail "pod-to-pod $dst saw $got"
done
kubectl -n $NS exec src-remote -- ping -c 3 "$(ip_of echo-b)"
ok "pod-to-pod same-node and cross-node, no SNAT"

echo "=== 5. CEGPs ==="
docker run -d --name ext --network kind $NETSHOOT sh -c "$ECHO"
EXT_IP=$(docker inspect ext -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "external host $EXT_IP; gateway $GW mac $GW_MAC; MC_EGRESS_IP=$MC_EGRESS_IP UC_EGRESS_IP=$UC_EGRESS_IP"
kubectl label node $GW egress-gw=true --overwrite
cat <<EOF | tee /dev/stderr | kubectl apply -f -
apiVersion: cilium.io/v2
kind: CiliumEgressGatewayPolicy
metadata: {name: mcast-egw}
spec:
  selectors: [{podSelector: {matchLabels: {app: egw-src}}}]
  destinationCIDRs: ["232.0.0.0/4"]
  egressGateway:
    nodeSelector: {matchLabels: {egress-gw: "true"}}
    egressIP: $MC_EGRESS_IP
---
apiVersion: cilium.io/v2
kind: CiliumEgressGatewayPolicy
metadata: {name: unicast-egw}
spec:
  selectors: [{podSelector: {matchLabels: {app: egw-src}}}]
  destinationCIDRs: ["$EXT_IP/32"]
  egressGateway:
    nodeSelector: {matchLabels: {egress-gw: "true"}}
    egressIP: $UC_EGRESS_IP
EOF
for i in $(seq 30); do
  n=$(dbg $OTHER cilium-dbg bpf egress list | grep -c -E "$MC_EGRESS_IP|$UC_EGRESS_IP" || true)
  [ "$n" -ge 4 ] && break; sleep 2
done
for n in $OTHER $GW; do echo "--- $n bpf egress list"; dbg $n cilium-dbg bpf egress list; done

echo "=== 6. unicast CEGP SNAT ==="
for p in src-remote src-local; do
  got=$(kubectl -n $NS exec $p -- curl -s --max-time 5 "$EXT_IP:8080")
  echo "$p($(ip_of $p)) -> ext $EXT_IP: peer=$got"
  [ "$got" = "$UC_EGRESS_IP" ] || fail "unicast CEGP from $p: ext saw $got, want $UC_EGRESS_IP"
done
ok "unicast CEGP SNATs to $UC_EGRESS_IP from remote and gateway-local sources"

echo "=== 7. multicast CEGP SNAT (tcpdump on the docker bridge every node's eth0 is plugged into) ==="
BR=br-$(docker network inspect kind -f '{{.Id}}' | cut -c1-12)
sudo tcpdump -nn -e -U -i "$BR" -w /tmp/mc.pcap 'udp and dst net 224.0.0.0/4 and dst portrange 5001-5002' &
TD=$!; sleep 2
send() { kubectl -n $NS exec "$1" -- sh -c \
  "for i in \$(seq 20); do echo blo45348-$1-\$i; sleep 0.1; done | socat -u - UDP4-DATAGRAM:$GROUP:$2,ip-multicast-ttl=8"; }
send src-remote 5001
send src-local 5002
sleep 2; sudo kill -INT $TD; wait $TD || true
sudo tcpdump -nn -e -r /tmp/mc.pcap | tee /tmp/mc.txt
for port in 5001 5002; do
  lines=$(grep "$GROUP.$port:" /tmp/mc.txt || true)
  total=$(printf '%s' "$lines" | grep -c . || true)
  good=$(printf '%s\n' "$lines" | grep -c "^.* $GW_MAC > .* $MC_EGRESS_IP\.[0-9]* > $GROUP.$port:" || true)
  echo "port $port: $total packets on the wire, $good with src=$MC_EGRESS_IP from $GW ($GW_MAC)"
  [ "$total" -ge 15 ] || fail "port $port: only $total/20 multicast packets left the cluster"
  [ "$good" -eq "$total" ] || fail "port $port: $((total-good)) packets not SNATed/emitted by gateway"
done
if grep -E ' 10\.244\.[0-9]+\.[0-9]+\.[0-9]+ > 232\.' /tmp/mc.txt; then fail "pod-sourced multicast leaked unSNATed"; fi
echo "dst MACs seen: $(awk '{print $4}' /tmp/mc.txt | sort | uniq -c | tr '\n' ';')"
ok "multicast CEGP: pod -> $GROUP leaves $GW with src=$MC_EGRESS_IP (remote-origin and gateway-local)"

echo "=== 8. unicast still SNATs after multicast traffic (coexistence) ==="
got=$(kubectl -n $NS exec src-remote -- curl -s --max-time 5 "$EXT_IP:8080")
[ "$got" = "$UC_EGRESS_IP" ] || fail "post-multicast unicast saw $got"
ok "unicast CEGP unchanged after multicast run"
echo "BAKE RESULT: PASS image=${IMAGE_DIGEST}"
