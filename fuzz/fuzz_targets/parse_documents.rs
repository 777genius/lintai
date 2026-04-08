#![no_main]

use libfuzzer_sys::fuzz_target;

fn assert_markdown_regions_are_bounded(input_len: usize, regions: &[lintai_api::TextRegion]) {
    let mut previous_start = 0usize;
    let mut previous_end = 0usize;

    for region in regions {
        assert!(region.span.start_byte <= region.span.end_byte);
        assert!(region.span.end_byte <= input_len);
        assert!(region.span.start_byte >= previous_start);
        assert!(region.span.end_byte >= previous_end);
        previous_start = region.span.start_byte;
        previous_end = region.span.end_byte;
    }
}

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let input = input.as_ref();

    let _ = lintai_parse::parse::json::parse(input);
    let _ = lintai_parse::parse::yaml::parse(input);

    if let Ok(parsed) = lintai_parse::parse::markdown::parse(input) {
        assert_markdown_regions_are_bounded(input.len(), &parsed.document.regions);
    }
});
