"""Bound untrusted dependency structures before recursive consumers see them."""

MAX_DEPENDENCY_STRUCTURE_DEPTH = 128


def validate_structure_depth(value: object) -> None:
    pending = [(value, 0)]
    deepest: dict[int, int] = {}
    while pending:
        node, depth = pending.pop()
        if not isinstance(node, (dict, list)):
            continue
        if depth > MAX_DEPENDENCY_STRUCTURE_DEPTH:
            raise ValueError("Dependency structure exceeds supported nesting depth")
        # YAML aliases may share or cycle through containers. Revisit only at
        # greater depth, so cycles fail at the same explicit depth bound.
        if deepest.get(id(node), -1) >= depth:
            continue
        deepest[id(node)] = depth
        children = node.values() if isinstance(node, dict) else node
        pending.extend(
            (child, depth + 1) for child in children if isinstance(child, (dict, list))
        )
