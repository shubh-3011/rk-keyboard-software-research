"""Offline candidate locations from installed 4.06 G5 ordinary serializer.

This is not a device codec, decoder, write policy, or evidence of hardware
behavior. Inputs must be independently obtained; no device or vendor process
is accessed. The mapped branch and special-row override deliberately fail closed.
"""


def ordinary_candidate_offset(*, row, row_count, led_mask, mapping_gate_sum,
                              special_row, selected_row):
    """Return a static candidate block offset for the narrowly selected branch."""
    values = (row, row_count, led_mask, mapping_gate_sum, special_row, selected_row)
    if any(type(value) is not int for value in values):
        raise ValueError('All selector inputs must be integers')
    if not 1 <= row_count <= 24 or not 0 <= row < row_count:
        raise ValueError('Row must be within the bounded runtime row count')
    if not 0 <= selected_row < row_count:
        raise ValueError('Selected row must be within the runtime row count')
    if not 0 <= led_mask <= 0xffffffff or not 0 <= special_row < 24:
        raise ValueError('Invalid mask or special row')
    if mapping_gate_sum != 0:
        raise ValueError('Only the observed zero-sum non-mapped branch is modeled')
    if led_mask & (1 << row):
        raise ValueError('Serializer skips this masked row')
    if row == special_row or selected_row == special_row:
        raise ValueError('Special-row override requires separate attribution')
    offset = 0x3a + 2 * row
    if offset >= 126:
        raise ValueError('Candidate falls outside configuration payload')
    return offset


def compare_candidate(before, changed, restored, *, row, row_count, led_mask,
                      mapping_gate_sum, special_row, selected_row):
    """Describe differences; even a match never grants hardware write permission."""
    offset = ordinary_candidate_offset(row=row, row_count=row_count, led_mask=led_mask,
                                       mapping_gate_sum=mapping_gate_sum, special_row=special_row,
                                       selected_row=selected_row)
    for block in (before, changed, restored):
        if not isinstance(block, bytes) or len(block) != 128 or block[-2:] != b'\x5a\xa5':
            raise ValueError('Each block must be 128 bytes with a valid trailer')
    differences = [i for i, (a, b) in enumerate(zip(before, changed)) if a != b]
    return {
        'candidate_offset': offset,
        'changed_offsets': differences,
        'only_candidate_changed': differences == [offset],
        'exact_block_restored': before == restored,
        'hardware_write_authorized': False,
        'limitation': 'Static candidate only; no causal, endpoint, family, profile or physical brightness attribution.',
    }
