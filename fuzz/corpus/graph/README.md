# Graph corpus anomalies

This corpus targets parser/graph construction edge cases. The table marks which anomaly types each file exercises.

Anomaly types:
- Header/EOF: invalid or missing PDF header/footer markers
- Xref/Trailer: malformed xref tables, missing/invalid trailers, inconsistent startxref
- Obj Syntax: malformed objects, missing endobj, invalid tokens
- Stream: stream keyword/length/endstream issues, unsupported filters
- ObjStm: object stream specific issues (/ObjStm)
- Refs/Names: invalid references, names, dict keys
- Numeric: malformed or overflow numeric tokens
- Whitespace/Binary: odd whitespace or stray binary bytes

| File | Header/EOF | Xref/Trailer | Obj Syntax | Stream | ObjStm | Refs/Names | Numeric | Whitespace/Binary |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| bad_objstm_n.pdf |  |  |  |  | X |  | X |  |
| bad_real_number.pdf |  |  | X |  |  |  | X |  |
| bad_token_stream.pdf |  |  |  | X |  |  |  | X |
| bad_xref.pdf |  | X |  |  |  |  |  |  |
| array_missing_bracket.pdf |  |  | X |  |  |  |  |  |
| bad_stream_filter_params.pdf |  |  |  | X |  |  | X |  |
| broken_stream_dict.pdf |  |  |  | X |  |  |  |  |
| broken_objstm.pdf |  |  |  |  | X |  | X |  |
| conflicting_trailer_size.pdf |  | X |  |  |  |  | X |  |
| dup_obj_id.pdf |  | X | X |  |  |  |  |  |
| extra_endobj.pdf |  |  | X |  |  |  |  |  |
| incomplete_xref_entry.pdf |  | X |  |  |  |  |  |  |
| incremental_update.pdf |  | X |  |  |  |  |  |  |
| invalid_boolean.pdf |  |  | X |  |  |  |  |  |
| invalid_comment.pdf |  |  |  |  |  |  |  | X |
| invalid_dict_key.pdf |  |  | X |  |  | X |  |  |
| invalid_header.pdf | X |  |  |  |  |  |  |  |
| invalid_hex_string.pdf |  |  | X |  |  |  |  |  |
| invalid_name_token.pdf |  |  |  |  |  | X |  |  |
| invalid_obj_header.pdf |  |  | X |  |  |  |  |  |
| invalid_dict_nested_array.pdf |  |  | X |  |  |  |  |  |
| invalid_ref.pdf |  |  |  |  |  | X |  |  |
| invalid_string_escape.pdf |  |  | X |  |  |  |  |  |
| invalid_string_literal.pdf |  |  | X |  |  |  |  |  |
| invalid_utf8_name.pdf |  |  |  |  |  | X |  | X |
| invalid_xref_format.pdf |  | X |  |  |  |  |  |  |
| long_number_tokens.pdf |  |  | X |  |  |  | X |  |
| malformed_array.pdf |  |  | X |  |  |  |  |  |
| malformed_ref_in_array.pdf |  |  | X |  |  | X |  |  |
| missing_header.pdf | X |  |  |  |  |  |  |  |
| missing_endobj.pdf |  |  | X |  |  |  |  |  |
| missing_endstream.pdf |  |  |  | X |  |  |  |  |
| missing_eof.pdf | X | X |  |  |  |  |  |  |
| missing_stream_keyword.pdf |  |  |  | X |  |  |  |  |
| multi_startxref.pdf |  | X |  |  |  |  |  |  |
| negative_length.pdf |  |  |  | X |  |  | X |  |
| negative_obj_number.pdf |  |  | X |  |  |  | X |  |
| nested_xref.pdf |  | X |  |  |  |  |  |  |
| objstm_missing_first.pdf |  |  |  |  | X |  |  |  |
| objstm_negative_first.pdf |  |  |  |  | X |  | X |  |
| odd_hex_escapes.pdf |  |  | X |  |  |  |  |  |
| overflow_integer.pdf |  |  | X |  |  |  | X |  |
| stream_length_mismatch.pdf |  |  |  | X |  |  |  |  |
| stray_binary.pdf |  |  |  |  |  |  |  | X |
| trailer_missing_size.pdf |  | X |  |  |  |  |  |  |
| truncated_stream.pdf |  |  |  | X |  |  |  |  |
| unterminated_dict.pdf |  |  | X |  |  |  |  |  |
| unsupported_filter.pdf |  |  |  | X |  |  |  |  |
| weird_whitespace.pdf |  |  |  |  |  |  |  | X |
| xref_subsection_mismatch.pdf |  | X |  |  |  |  |  |  |
| xref_missing_trailer.pdf |  | X |  |  |  |  |  |  |
| xref_negative_offset.pdf |  | X |  |  |  |  | X |  |
| xref_overlap.pdf |  | X |  |  |  |  |  |  |
| xref_with_gaps.pdf |  | X |  |  |  |  |  |  |
| xref_zero_entries.pdf |  | X |  |  |  |  |  |  |
| zero_length_filtered_stream.pdf |  |  |  | X |  |  |  |  |
| malformed_indirect_ref.pdf |  |  |  |  |  | X |  |  |
