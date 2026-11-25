#!/bin/bash
# Update §5.6 obligations with new test evidence

jq '
.atomic_requirements = [
  .atomic_requirements[] | 
  if .id == "RFC9171-5-034" then
    .state = "implemented_unverified" |
    .test_evidence = ["test_rfc9171_5_6_reception_status_report_requested", "test_rfc9171_5_6_no_reports_for_admin_records"] |
    .evidence_note = "Reception status report generation per §5.6 Step 2. Tests verify REQUEST_REPORT_RECEPTION flag (bit 14) is checked and that admin records (bit 1) do not generate reports per §6.1." |
    del(.gap_id)
  elif .id == "RFC9171-5-039" then
    .state = "implemented_unverified" |
    .test_evidence = ["test_rfc9171_5_6_report_on_unsupported_block", "test_reception_reports_on_unsupported_reportable_block"] |
    .evidence_note = "Block processing control flag bit 1 (REPORT_ON_FAILURE = 0x02): Status report with reason \"Block unsupported\" SHOULD be generated per §5.6 Step 4." |
    del(.gap_id)
  elif .id == "RFC9171-5-040" then
    .state = "implemented_unverified" |
    .test_evidence = (.test_evidence + ["test_rfc9171_5_6_delete_on_critical_unsupported_block", "test_reception_deletes_on_unsupported_critical_block", "test_rfc9171_5_6_flag_priority"]) | unique |
    .evidence_note = "Block processing control flag bit 2 (DELETE_BUNDLE_ON_FAILURE = 0x04): Bundle MUST be deleted with reason \"Block unsupported\" per §5.6 Step 4."
  elif .id == "RFC9171-5-043" then
    .state = "implemented_unverified" |
    .test_evidence = ["test_rfc9171_5_6_discard_unsupported_block", "test_reception_discards_unsupported_discardable_block", "test_rfc9171_5_6_multiple_unsupported_blocks"] |
    .evidence_note = "Block processing control flag bit 4 (DISCARD_BLOCK_ON_FAILURE = 0x10): Unsupported block MUST be removed from bundle per §5.6 Step 4." |
    del(.gap_id)
  else
    .
  end
] |
.coverage_summary.implemented_unverified = ([.atomic_requirements[] | select(.state == "implemented_unverified")] | length) |
.coverage_summary.not_started = (230 - .coverage_summary.implemented_unverified) |
.coverage_summary.coverage_percentage = ((.coverage_summary.implemented_unverified / 230 * 1000 | round) / 10)
' spec/requirements-atomic.json > spec/requirements-atomic.json.tmp && mv spec/requirements-atomic.json.tmp spec/requirements-atomic.json

echo "Updated obligations:"
jq '.coverage_summary' spec/requirements-atomic.json
