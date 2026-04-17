use rsip::headers::UntypedHeader;

pub mod accept;
pub mod alert_info;
pub mod allow;
pub mod auth;
pub mod authentication_info;
pub mod authorization;
pub mod call_info;
pub mod contact;
pub mod content_disposition;
pub mod content_length;
pub mod content_type;
pub mod cseq;
pub mod error_info;
pub mod from;
pub mod in_reply_to;
pub mod max_forwards;
pub mod media_type;
pub mod priority;
pub mod proxy_authenticate;
pub mod record_route;
pub mod reply_to;
pub mod to;
pub mod tokenizers;
pub mod via;
pub mod warning;
pub mod www_authenticate;

use rsip::headers::{header::Tokenizer, Accept, Header};

mod name_and_value {
    use rsip::headers::*;
    use rsip::Header;

    #[test]
    fn single_word_header() {
        let header = Header::Via(Via::new("SIP/2.0/UDP 192.168.1.1"));
        assert_eq!(header.name(), "Via");
        assert_eq!(header.value(), "SIP/2.0/UDP 192.168.1.1");
    }

    #[test]
    fn multi_word_header() {
        let header = Header::ContentLength(ContentLength::new("349"));
        assert_eq!(header.name(), "Content-Length");
        assert_eq!(header.value(), "349");
    }

    #[test]
    fn explicit_display_name_call_id() {
        let header = Header::CallId(CallId::new("abc@example.com"));
        assert_eq!(header.name(), "Call-ID");
        assert_eq!(header.value(), "abc@example.com");
    }

    #[test]
    fn explicit_display_name_cseq() {
        let header = Header::CSeq(CSeq::new("1 INVITE"));
        assert_eq!(header.name(), "CSeq");
        assert_eq!(header.value(), "1 INVITE");
    }

    #[test]
    fn explicit_display_name_www_authenticate() {
        let header = Header::WwwAuthenticate(WwwAuthenticate::new("Digest realm=\"example.com\""));
        assert_eq!(header.name(), "WWW-Authenticate");
        assert_eq!(header.value(), "Digest realm=\"example.com\"");
    }

    #[test]
    fn other_variant() {
        let header = Header::Other("X-Custom".into(), "some-value".into());
        assert_eq!(header.name(), "X-Custom");
        assert_eq!(header.value(), "some-value");
    }
}

mod display {
    use super::*;

    #[test]
    fn display1() {
        assert_eq!(
            Header::Accept(Accept::new("REGISTER, INVITE")).to_string(),
            String::from("Accept: REGISTER, INVITE")
        );
    }

    #[test]
    fn display2() {
        assert_eq!(
            Header::Other("X-Forward".into(), "202.45.213.14".into()).to_string(),
            String::from("X-Forward: 202.45.213.14")
        );
    }
}

mod tokenizer {
    use super::*;

    #[test]
    fn tokenizer1() {
        assert_eq!(
            Tokenizer::tokenize(b"Accept: REGISTER, INVITE\r\n something"),
            Ok((
                " something".as_bytes(),
                Tokenizer {
                    name: "Accept".as_bytes(),
                    value: "REGISTER, INVITE".as_bytes()
                }
            )),
        );
    }
}
