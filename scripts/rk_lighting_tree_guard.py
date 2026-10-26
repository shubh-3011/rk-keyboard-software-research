"""Pure context guard for the one observed installed-4.06 lighting fixture."""


def validate_tree(items, original, remaining_item, row_height):
    if (len(items) not in (19, 20) or remaining_item or len(set(items)) != len(items)
            or any(not item for item in items) or original != items[18]
            or not 10 <= row_height <= 80):
        raise ValueError('Not the observed lighting tree (19 rows plus optional Music) with original Off row 18; no UI action permitted')
