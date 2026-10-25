"""Generated contract predicates; edit formal/contracts.json, then regenerate."""
# BEGIN GENERATED VERIFIED GUARDS
def _contract_argument(value, kind):
    valid = (type(value) is int and value >= 0) if kind == "Nat" else type(value) is bool if kind == "Bool" else type(value) is str if kind == "String" else type(value) is list and all(type(item) is bool for item in value)
    if not valid: raise ValueError("verified guard argument outside its proved domain: " + kind)


def credit_reservable(available, amount):
    _contract_argument(available, 'Nat')
    _contract_argument(amount, 'Nat')
    return (amount <= available)


def credit_acknowledgeable(outstanding, amount):
    _contract_argument(outstanding, 'Nat')
    _contract_argument(amount, 'Nat')
    return (amount <= outstanding)


def capability_allowed(build, grant, policy, domain):
    _contract_argument(build, 'Bool')
    _contract_argument(grant, 'Bool')
    _contract_argument(policy, 'Bool')
    _contract_argument(domain, 'Bool')
    return (build and grant and policy and domain)


def chat_peer_bound(local_name, recipient, peer, sender):
    _contract_argument(local_name, 'String')
    _contract_argument(recipient, 'String')
    _contract_argument(peer, 'String')
    _contract_argument(sender, 'String')
    return ((local_name == recipient) and (peer == sender))


# END GENERATED VERIFIED GUARDS
