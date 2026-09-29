# ironcore-dev-key-exchange

Key exchange for the IPsec encryption of dpservice. All hosts of a VNI form an
[MLS](https://www.rfc-editor.org/rfc/rfc9420.html) group. From the group secret of every epoch,
each host derives the keys of the IPsec Security Associations (SAs) towards every other host of
the VNI and installs them in its dpservice.

## Components

| Component | Where | Role |
|---|---|---|
| **Client** (metalnet) | every host | Tells the agent which VNIs the host takes part in (`pkg/client`) |
| **dpservice** | every host | Dataplane, holds the SAs. Its SA API has no list call |
| **Agent** (`mls_key_exchange`) | every host, exactly one per dpservice | Member of the MLS groups, manages the SAs in its dpservice. Its MLS state lives in the Rust backend (`rust_backend`) in the same container |
| **MLS Server** (`mls_server`) | once | Delivery service and coordinator: mailboxes, key packages, group membership and rekey rounds |

The agent's identity is the underlay /64 prefix of its host (for example `fc00:1::/64`). Because
there is exactly one dpservice per host, it is unique and stable, and it can be read back from
dpservice after a restart.

## Resilience

Neither the agents nor the server store any state. The **SAs in dpservice are the only state that
survives a crash**, and everything else is rebuilt from them:

- **SA slots:** each direction of a host pair has two slots. Their SPIs are derived only from
  VNI, the two underlay prefixes and the slot number. A restarted agent finds its SAs again by
  probing both slots with `GetSecurityAssociation`.
- **Make-before-break rekey:** after every change of the MLS epoch, all host pairs are rekeyed in
  a round of four phases. The receiver installs the new ingress SA first, then the sender
  switches its egress SA (`UpdateSecurityAssociation`, without a gap), and finally the old
  ingress SA is removed. If a crash interrupts a round, the old SAs remain in place.
- **Nothing is deleted by accident:** host pairs with a peer that is not currently part of the
  MLS group are never touched. SAs are only deleted in the cleanup phase of a round or when a
  host unsubscribes.

## Communication flows

In the diagrams, *A*, *B* and *C* are hosts. Each has its own agent and dpservice.

### Initial setup: create a group and join it

The first agent to subscribe to a VNI creates the MLS group and becomes its **committer**. The
committer is the only member that makes commits for the group. Every later agent is added by the
committer.

```mermaid
sequenceDiagram
    participant CA as Client A
    participant AA as Agent A
    participant DA as dpservice A
    participant S as MLS Server
    participant AB as Agent B
    participant DB as dpservice B
    participant CB as Client B

    CA->>AA: Init(prefix fc00:1::/64)
    AA->>AA: identity = fc00:1::/64, new MLS credential
    AA->>S: /register
    AA->>S: /upload_kp (x10)
    AA->>DA: ListInterfaces (VNIs to recover: none)
    AA->>S: /poll (long-poll loop)

    CA->>AA: Subscribe(VNI 100)
    AA->>S: /subscribe(has_group=0)
    S-->>AA: created
    AA->>AA: CreateGroup, epoch 0
    AA->>S: /ready(epoch 0)
    Note over S: only one member, nothing to rekey

    CB->>AB: Init(prefix fc00:2::/64)
    AB->>S: /register, /upload_kp (x10)
    CB->>AB: Subscribe(VNI 100)
    AB->>S: /subscribe(has_group=0)
    S-->>AB: joining
    S->>AA: op: add(B)
    AA->>S: /get_kp(B)
    AA->>AA: SwapMember(B), epoch 1
    AA->>S: /send welcome to B
    AA->>S: /op_done(epoch 1, members A B)
    AA->>S: /ready(epoch 1)
    S->>AB: welcome
    AB->>AB: JoinGroup, epoch 1
    AB->>S: /ready(epoch 1)

    Note over AA,AB: all members reached epoch 1: rekey round (next diagram)

    CB->>AB: IsKeyReady(VNI 100)
    AB-->>CB: true (after the switch phase)
```

### Rekey round

This round runs after every epoch change: a join, a leave, a re-add after a restart, or a key
rotation. The server starts each phase only after all members have acknowledged the previous one.
Below it is shown for one host pair. The same happens for all pairs of the group at the same
time.

```mermaid
sequenceDiagram
    participant DA as dpservice A
    participant AA as Agent A
    participant S as MLS Server
    participant AB as Agent B
    participant DB as dpservice B

    Note over AA,AB: both export the group secret of the new epoch

    rect rgb(235, 245, 255)
    Note over S: phase prepare
    S->>AA: round_prepare(peers)
    S->>AB: round_prepare(peers)
    AA->>DA: GetSA egress A→B slot 0/1 (only if not known, e.g. after a restart)
    AA->>S: /round_ack prepare: egress to B in slot 0
    AB->>S: /round_ack prepare: egress to A in slot 0
    end

    rect rgb(235, 255, 235)
    Note over S: phase install
    S->>AA: round_install(B sends in slot 0)
    S->>AB: round_install(A sends in slot 0)
    AA->>DA: CreateSA ingress B→A slot 1 (new key)
    AB->>DB: CreateSA ingress A→B slot 1 (new key)
    AA->>S: /round_ack install
    AB->>S: /round_ack install
    end

    rect rgb(255, 250, 230)
    Note over S: phase switch
    S->>AA: round_switch
    S->>AB: round_switch
    AA->>DA: UpdateSA egress A→B slot 0 → slot 1 (no gap)
    AB->>DB: UpdateSA egress B→A slot 0 → slot 1 (no gap)
    AA->>S: /round_ack switch
    AB->>S: /round_ack switch
    end

    rect rgb(255, 235, 235)
    Note over S: phase cleanup
    S->>AA: round_cleanup
    S->>AB: round_cleanup
    AA->>DA: DeleteSA ingress B→A slot 0 (old key)
    AB->>DB: DeleteSA ingress A→B slot 0 (old key)
    end
```

On an egress SA, the only change is the switch to an ingress SA that the peer has already
installed. An ingress SA is only deleted after every sender has confirmed it no longer uses it.
So at every moment, both ends of a pair can decrypt what the other end sends.

### Key rotation

Every 60 minutes, the server rotates the keys of every group with at least two members. The
interval can be changed with `MLS_KEY_ROTATION_INTERVAL`. The committer makes an MLS self-update
commit, which moves the group to a new epoch with a fresh group secret. The rekey round of that
epoch then replaces the SAs of all pairs, without a gap in traffic. So even a group whose
membership never changes gets new keys regularly, and no SA stays in use long enough to exhaust
its sequence numbers.

A rotation is queued like any other membership operation, so it never runs concurrently with a
join, a leave or a re-add. A group that still has a rotation waiting doesn't get a second one,
for example while it is stalled by a dead member.

```mermaid
sequenceDiagram
    participant DA as dpservice A
    participant AA as Agent A (committer)
    participant S as MLS Server
    participant AB as Agent B
    participant DB as dpservice B

    Note over S: every 60 minutes, per group with at least 2 members
    S->>S: queue op update (skipped if one is still queued)
    S->>AA: op: update
    AA->>AA: SelfUpdate: new epoch, fresh group secret
    AA->>S: /send commit to B
    AA->>S: /op_done(new epoch)
    AA->>S: /ready(new epoch)
    S->>AB: commit
    AB->>AB: ProcessCommit, new epoch
    AB->>S: /ready(new epoch)

    Note over AA,AB: rekey round with keys from the new group secret
    AA->>DA: install: CreateSA new ingress
    AB->>DB: install: CreateSA new ingress
    AA->>DA: switch: UpdateSA egress
    AB->>DB: switch: UpdateSA egress
    AA->>DA: cleanup: DeleteSA old ingress
    AB->>DB: cleanup: DeleteSA old ingress
```

### Agent crash or restart

dpservice keeps running, and with it all SAs, so traffic keeps flowing. The restarted agent gets
everything it needs from dpservice, so it doesn't need the Client to call `Init` again. If the
Client does call `Init` again, the call does nothing.

```mermaid
sequenceDiagram
    participant CB as Client B
    participant AB as Agent B
    participant DB as dpservice B
    participant S as MLS Server
    participant AA as Agent A (committer)
    participant DA as dpservice A

    Note over AB: crash: MLS state lost
    Note over DA,DB: SAs unchanged, traffic keeps flowing

    AB->>AB: restart
    AB->>DB: ListInterfaces
    DB-->>AB: underlay fc00:2::5, VNI 100 encrypted
    AB->>AB: identity = fc00:2::/64 (same as before), new MLS credential
    AB->>S: /register (drops old mailbox and key packages)
    AB->>S: /upload_kp (x10)
    AB->>S: /subscribe(VNI 100, has_group=0)
    S-->>AB: joining
    S->>AA: op: readd(B)
    AA->>AA: SwapMember(B): replaces B's old leaf in one commit
    AA->>S: /send welcome to B, /op_done
    S->>AB: welcome
    AB->>AB: JoinGroup

    Note over AA,AB: rekey round
    AB->>DB: prepare: GetSA both slots, both directions towards A
    DB-->>AB: egress to A in slot 0, ingress from A in slot 0
    Note over AA,AB: install, switch, cleanup as usual: new keys for all pairs with B

    opt Client calls Init again
        CB->>AB: Init(fc00:2::/64)
        AB-->>CB: ok (already initialized, nothing to do)
    end
```

### Committer crash

If the agent that crashed was the committer, the server hands the committer role to another
member. An operation that was still assigned to the old committer is handed over too. A dead
committer that doesn't come back is replaced by the housekeeping loop once it hasn't polled for
45s.

```mermaid
sequenceDiagram
    participant AA as Agent A (committer)
    participant S as MLS Server
    participant AB as Agent B
    participant AC as Agent C

    Note over AA: crash
    AA->>S: /register, /subscribe(has_group=0) after restart
    S->>S: committer A → B (hands over any open operation)
    S-->>AA: joining
    S->>AB: op: readd(A)
    AB->>AB: SwapMember(A)
    AB->>S: /send commit to C
    AB->>S: /send welcome to A
    AB->>S: /op_done
    S->>AC: commit
    S->>AA: welcome
    Note over AA,AC: rekey round, B stays committer
```

### MLS server crash or restart

The server loses all state, but none of the SAs are affected. The agents notice the restart by
the changed boot ID in the poll responses. They then register and subscribe again, and the groups
are rebuilt from scratch. The old SAs stay in use until the new group has rekeyed each pair.

```mermaid
sequenceDiagram
    participant DA as dpservice A
    participant AA as Agent A
    participant S as MLS Server
    participant AB as Agent B
    participant DB as dpservice B

    Note over S: crash, all state lost
    Note over DA,DB: SAs unchanged, traffic keeps flowing
    S->>S: restart with new boot ID

    AA->>S: /poll
    S-->>AA: response header with new boot ID
    AA->>S: /register, /upload_kp (x10)
    AA->>S: /subscribe(VNI 100, has_group=1)
    S-->>AA: created (no group known)
    AA->>AA: drop old group, CreateGroup, epoch 0

    AB->>S: /poll
    S-->>AB: new boot ID
    AB->>S: /register, /upload_kp (x10)
    AB->>S: /subscribe(VNI 100, has_group=1)
    S-->>AB: joining
    AB->>AB: drop old group
    S->>AA: op: add(B)
    AA->>S: /send welcome to B, /op_done
    S->>AB: welcome

    Note over AA,AB: rekey round: slots come from the agents' caches and dpservice
    AA->>DA: UpdateSA egress (switch)
    AB->>DB: UpdateSA egress (switch)
```

### Agents and server restart together

This combines the two cases above. Every agent recovers from its own dpservice, and the first
agent to reach the new server creates the group. There is no difference between a *restarted*
and a *fresh* server from the agents' point of view.

```mermaid
sequenceDiagram
    participant DA as dpservice A
    participant AA as Agent A
    participant S as MLS Server
    participant AB as Agent B
    participant DB as dpservice B

    Note over AA,AB: everything crashes, only dpservice keeps the SAs
    AA->>DA: ListInterfaces (identity, VNIs)
    AB->>DB: ListInterfaces (identity, VNIs)
    AA->>S: /register, /subscribe(has_group=0)
    S-->>AA: created
    AB->>S: /register, /subscribe(has_group=0)
    S-->>AB: joining
    S->>AA: op: add(B)
    AA->>S: /send welcome to B
    S->>AB: welcome
    Note over AA,AB: rekey round
    AA->>DA: GetSA probing
    AB->>DB: GetSA probing
    Note over AA,AB: SA state recovered, then install, switch and cleanup
```

### Crash during a rekey round

A round only moves forward when every member has acknowledged the current phase. If a member dies
in the middle of a round, the round stalls. The SAs stay in a consistent state, with at most one
extra ingress SA per pair. After a 20s timeout, the server continues with the next operation,
which is usually re-adding the crashed member. The next round removes any stale SAs.

```mermaid
sequenceDiagram
    participant AA as Agent A
    participant S as MLS Server
    participant AB as Agent B
    participant DB as dpservice B

    S->>AA: round_install (epoch 3)
    S->>AB: round_install (epoch 3)
    AB->>DB: CreateSA ingress A→B slot 1
    AB->>S: /round_ack install
    Note over AA: crash before its ack
    Note over S: round of epoch 3 stalls: no switch, old egress SAs stay in use
    Note over AB,DB: A→B still uses slot 0, which B can still decrypt

    AA->>S: /register, /subscribe(has_group=0) after restart
    Note over S: after 20s the stalled round no longer blocks
    S->>AB: op: readd(A)
    Note over AA,AB: round of epoch 4
    AB->>S: prepare: egress to A in slot 0
    AA->>S: prepare: egress to B in slot 0 (probed from dpservice)
    AB->>DB: install: replace stale ingress A→B slot 1 with the new key
    Note over AA,AB: switch and cleanup as usual
```

### Host reboot

When the whole host reboots, dpservice comes back empty and the Client sets it up again, so there
is nothing to recover. On the peers, the SAs towards the rebooted host are still there. They are
replaced by the first rekey round once the host has been re-added.

```mermaid
sequenceDiagram
    participant CB as Client B
    participant AB as Agent B
    participant DB as dpservice B
    participant S as MLS Server
    participant AA as Agent A (committer)
    participant DA as dpservice A

    Note over AB,DB: host B reboots, dpservice B is empty
    Note over DA: still has SAs towards B (slot 0)
    CB->>DB: recreate interfaces
    CB->>AB: Init(fc00:2::/64)
    AB->>S: /register, /upload_kp (x10)
    CB->>AB: Subscribe(VNI 100)
    AB->>S: /subscribe(has_group=0)
    S->>AA: op: readd(B)
    AA->>S: /send welcome to B
    S->>AB: welcome

    Note over AA,AB: rekey round
    AB->>S: prepare: no egress to A
    AA->>S: prepare: egress to B in slot 0
    AB->>DB: install: CreateSA ingress A→B slot 1
    AA->>DA: install: CreateSA ingress B→A slot 0 (replaces the stale one)
    AB->>DB: switch: CreateSA egress B→A slot 0
    AA->>DA: switch: UpdateSA egress A→B slot 0 → 1
    AA->>DA: cleanup: nothing old left
```

### Unsubscribe

When a host leaves a VNI, it removes all of its SAs for that VNI. The server tells the remaining
members to delete their SAs towards the leaving host, then the committer removes the host from
the MLS group. The remaining pairs get new keys in the following round.

```mermaid
sequenceDiagram
    participant CB as Client B
    participant AB as Agent B
    participant DB as dpservice B
    participant S as MLS Server
    participant AA as Agent A (committer)
    participant DA as dpservice A
    participant AC as Agent C

    CB->>AB: Unsubscribe(VNI 100)
    AB->>S: /unsubscribe
    AB->>AB: drop group
    AB->>DB: ListRoutes (find all peers, even after a restart)
    AB->>DB: DeleteSA all SAs of VNI 100
    S->>AA: peer_left(B)
    S->>AC: peer_left(B)
    AA->>DA: DeleteSA all SAs towards B
    S->>AA: op: remove(B)
    AA->>AA: RemoveMember(B)
    AA->>S: /send commit to C, /op_done
    Note over AA,AC: rekey round for the remaining pairs
```

## Configuration

| Variable | Used by | Default | Meaning |
|---|---|---|---|
| `MLS_SERVER_ADDRESS` | agent | – | URL of the MLS server, e.g. `http://mls-server:4713` |
| `RUST_GRPC_URL` | agent | – | Address of the Rust MLS backend, e.g. `127.0.0.1:50051` |
| `DPSERVICE_ADDRESS` | agent | `127.0.0.1:1337` | gRPC address of dpservice |
| `AGENT_LISTEN_ADDRESS` | agent | `[::]:50052` | gRPC address of the agent API for the Client |
| `RUST_GRPC_LISTEN` | rust backend | `[::]:50051` | gRPC address of the Rust MLS backend |
| `MLS_KEY_ROTATION_INTERVAL` | server | `60m` | Interval of the regular key rotation, as a Go duration (e.g. `30m`, `2h`) |

## Limitations

- An agent that dies and never comes back stops the rekeys of its groups. Rounds stall safely,
  and each membership operation waits for a timeout, but the dead agent is never removed
  automatically.
- If dpservice restarts while its agent keeps running, the agent's cached view of its SAs is out
  of date and its next rekey round stalls. A host reboot restarts both, so it isn't affected.
- dpservice holds at most 64 SAs per host (`DP_IPSEC_MAX_SA`). With two SAs per peer, plus one
  extra during a rekey, that is about 21 peers across all VNIs of a host.
