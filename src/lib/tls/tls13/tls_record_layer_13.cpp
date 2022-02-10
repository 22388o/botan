/*
* TLS Client - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_version.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>

#include <botan/internal/tls_record_layer_13.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

namespace {

template <typename IteratorT>
bool verify_change_cipher_spec(const IteratorT data, const size_t size)
   {
   // RFC 8446 5.
   //    An implementation may receive an unencrypted record of type
   //    change_cipher_spec consisting of the single byte value 0x01
   //    at any time [...]. An implementation which receives any other
   //    change_cipher_spec value or which receives a protected
   //    change_cipher_spec record MUST abort the handshake [...].
   const size_t expected_fragment_length = 1;
   const uint8_t expected_fragment_byte = 0x01;
   return (size == expected_fragment_length && *data == expected_fragment_byte);
   }

Record_Type read_record_type(const uint8_t type_byte)
   {
   // RFC 8446 5.
   //    If a TLS implementation receives an unexpected record type,
   //    it MUST terminate the connection with an "unexpected_message" alert.
   if(type_byte != Record_Type::APPLICATION_DATA
         && type_byte != Record_Type::HANDSHAKE
         && type_byte != Record_Type::ALERT
         && type_byte != Record_Type::CHANGE_CIPHER_SPEC)
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "unexpected message received");
      }

   return static_cast<Record_Type>(type_byte);
   }

/**
 * RFC 8446 5.1 `TLSPlaintext` without the `fragment` payload data
 */
struct TLSPlaintext_Header
   {
   TLSPlaintext_Header(std::vector<uint8_t> hdr, const bool initial_record)
      {
      type            = read_record_type(hdr[0]);
      legacy_version  = Protocol_Version(make_uint16(hdr[1], hdr[2]));
      fragment_length = make_uint16(hdr[3], hdr[4]);
      serialized      = std::move(hdr);

      // RFC 8446 5.1
      //    MUST be set to 0x0303 for all records generated by a TLS 1.3
      //    implementation other than an initial ClientHello [...], where
      //    it MAY also be 0x0301 for compatibility purposes.
      if(legacy_version.version_code() != 0x0303 &&
            !(initial_record && legacy_version.version_code() == 0x0301))
         { throw TLS_Exception(Alert::PROTOCOL_VERSION, "invalid record version"); }

      // RFC 8446 5.1
      //    Implementations MUST NOT send zero-length fragments of Handshake
      //    types, even if those fragments contain padding.
      //
      //    Zero-length fragments of Application Data MAY be sent, as they are
      //    potentially useful as a traffic analysis countermeasure.
      if(fragment_length == 0 && type != Record_Type::APPLICATION_DATA)
         { throw TLS_Exception(Alert::DECODE_ERROR, "empty record received"); }

      if(type == Record_Type::APPLICATION_DATA)
         {
         // RFC 8446 5.2
         //    The length [...] is the sum of the lengths of the content and the
         //    padding, plus one for the inner content type, plus any expansion
         //    added by the AEAD algorithm. The length MUST NOT exceed 2^14 + 256 bytes.
         if(fragment_length > MAX_CIPHERTEXT_SIZE_TLS13)
            { throw TLS_Exception(Alert::RECORD_OVERFLOW, "overflowing record received"); }
         }
      else
         {
         // RFC 8446 5.1
         //    The length MUST NOT exceed 2^14 bytes.  An endpoint that receives a record that
         //    exceeds this length MUST terminate the connection with a "record_overflow" alert.
         if(fragment_length > MAX_PLAINTEXT_SIZE)
            { throw TLS_Exception(Alert::RECORD_OVERFLOW, "overflowing record received"); }
         }
      }

   TLSPlaintext_Header(const Record_Type record_type,
                       const size_t frgmnt_length,
                       const bool use_compatibility_version)
      : type(record_type)
      , legacy_version(use_compatibility_version ? 0x0301 : 0x0303)  // RFC 8446 5.1
      , fragment_length(static_cast<uint16_t>(frgmnt_length))
      , serialized(
      {
      static_cast<uint8_t>(type),
      legacy_version.major_version(), legacy_version.minor_version(),
      get_byte<0>(fragment_length), get_byte<1>(fragment_length),
      })
      {}

   Record_Type          type;
   Protocol_Version     legacy_version;
   uint16_t             fragment_length;
   std::vector<uint8_t> serialized;
   };

}  // namespace

Record_Layer::Record_Layer(Connection_Side side)
   : m_side(side), m_initial_record(true) {}


void Record_Layer::copy_data(const std::vector<uint8_t>& data_from_peer)
   {
   m_read_buffer.insert(m_read_buffer.end(), data_from_peer.cbegin(), data_from_peer.cend());
   }

std::vector<uint8_t> Record_Layer::prepare_records(const Record_Type type,
      const std::vector<uint8_t>& data,
      Cipher_State* cipher_state)
   {
   const bool protect = cipher_state != nullptr;

   BOTAN_ASSERT(!m_initial_record || m_side == Connection_Side::CLIENT,
                "the initial record is always sent by the client");

   // RFC 8446 5.1
   BOTAN_ASSERT(protect || type != Record_Type::APPLICATION_DATA,
                "Application Data records MUST NOT be written to the wire unprotected");

   // RFC 8446 5.1
   //   "MUST NOT sent zero-length fragments of Handshake types"
   //   "a record with an Alert type MUST contain exactly one message" [of non-zero length]
   //   "Zero-length fragments of Application Data MAY be sent"
   BOTAN_ASSERT(data.size() != 0 || type == Record_Type::APPLICATION_DATA,
                "zero-length fragments of types other than application data are not allowed");

   if(type == Record_Type::CHANGE_CIPHER_SPEC &&
         !verify_change_cipher_spec(data.cbegin(), data.size()))
      {
      throw Invalid_Argument("TLS 1.3 deprecated CHANGE_CIPHER_SPEC");
      }

   std::vector<uint8_t> output;

   // calculate the final buffer length to prevent unneccesary reallocations
   const auto records = std::max((data.size() + MAX_PLAINTEXT_SIZE - 1) / MAX_PLAINTEXT_SIZE, size_t(1));
   auto output_length = records * TLS_HEADER_SIZE;
   if(protect)
      {
      output_length += cipher_state->encrypt_output_length(MAX_PLAINTEXT_SIZE + 1 /* for content type byte */) *
                       (records - 1);
      output_length += cipher_state->encrypt_output_length(data.size() % MAX_PLAINTEXT_SIZE + 1);
      }
   else
      {
      output_length += data.size();
      }
   output.reserve(output_length);

   size_t pt_offset = 0;
   size_t to_process = data.size();

   // For protected records we need to write at least one encrypted fragment,
   // even if the plaintext size is zero. This happens only for Application
   // Data types.
   BOTAN_ASSERT_NOMSG(to_process != 0 || protect);
   do
      {
      const size_t pt_size = std::min<size_t>(to_process, MAX_PLAINTEXT_SIZE);
      const size_t ct_size = (!protect) ? pt_size : cipher_state->encrypt_output_length(pt_size +
                             1 /* for content type byte */);
      const auto   pt_type = (!protect) ? type : Record_Type::APPLICATION_DATA;

      // RFC 8446 5.1
      //    MUST be set to 0x0303 for all records generated by a TLS 1.3
      //    implementation other than an initial ClientHello [...], where
      //    it MAY also be 0x0301 for compatibility purposes.
      const auto use_compatibility_version = m_side == Connection_Side::CLIENT && m_initial_record;
      const auto record_header = TLSPlaintext_Header(pt_type, ct_size, use_compatibility_version).serialized;
      m_initial_record = false;

      output.reserve(output.size() + record_header.size() + ct_size);
      output.insert(output.end(), record_header.cbegin(), record_header.cend());

      if(protect)
         {
         secure_vector<uint8_t> fragment;
         fragment.reserve(ct_size);

         // assemble TLSInnerPlaintext structure
         fragment.insert(fragment.end(), data.cbegin() + pt_offset, data.cbegin() + pt_offset + pt_size);
         fragment.push_back(static_cast<uint8_t>(type));
         // TODO: zero padding could go here, see RFC 8446 5.4

         cipher_state->encrypt_record_fragment(record_header, fragment);
         BOTAN_ASSERT_NOMSG(fragment.size() == ct_size);

         output.insert(output.end(), fragment.cbegin(), fragment.cend());
         }
      else
         {
         output.insert(output.end(), data.cbegin() + pt_offset, data.cbegin() + pt_offset + pt_size);
         }

      pt_offset += pt_size;
      to_process -= pt_size;
      }
   while(to_process > 0);

   BOTAN_ASSERT_NOMSG(output.size() == output_length);
   return output;
   }

std::vector<uint8_t> Record_Layer::prepare_dummy_ccs_record()
   {
   BOTAN_ASSERT(!m_initial_record, "CCS must not be the initial record");

   std::vector<uint8_t> data = {0x01};
   return prepare_records(Record_Type::CHANGE_CIPHER_SPEC, data);
   }


Record_Layer::ReadResult<Record> Record_Layer::next_record(Cipher_State* cipher_state)
   {
   BOTAN_ASSERT(!m_initial_record || m_side == Connection_Side::SERVER,
                "the initial record is always received by the server");

   if(m_read_buffer.size() < TLS_HEADER_SIZE)
      {
      return TLS_HEADER_SIZE - m_read_buffer.size();
      }

   const auto header_begin = m_read_buffer.cbegin();
   const auto header_end   = header_begin + TLS_HEADER_SIZE;
   TLSPlaintext_Header plaintext_header({header_begin, header_end}, m_initial_record);

   if(m_read_buffer.size() < TLS_HEADER_SIZE + plaintext_header.fragment_length)
      {
      return TLS_HEADER_SIZE + plaintext_header.fragment_length - m_read_buffer.size();
      }

   const auto fragment_begin = header_end;
   const auto fragment_end   = fragment_begin + plaintext_header.fragment_length;

   if(plaintext_header.type == Record_Type::CHANGE_CIPHER_SPEC &&
         !verify_change_cipher_spec(fragment_begin, plaintext_header.fragment_length))
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE,
                          "malformed change cipher spec record received");
      }

   Record record(plaintext_header.type, secure_vector<uint8_t>(fragment_begin, fragment_end));
   m_read_buffer.erase(header_begin, fragment_end);

   if(record.type == Record_Type::APPLICATION_DATA)
      {
      if(cipher_state == nullptr)
         {
         // This could also mean a misuse of the interface, i.e. failing to provide a valid
         // cipher_state to parse_records when receiving valid (encrypted) Application Data.
         throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "premature Application Data received");
         }

      record.seq_no = cipher_state->decrypt_record_fragment(plaintext_header.serialized, record.fragment);

      // hydrate the actual content type from TLSInnerPlaintext
      record.type = read_record_type(record.fragment.back());

      if(record.type == Record_Type::CHANGE_CIPHER_SPEC)
         {
         // RFC 8446 5
         //  An implementation [...] which receives a protected change_cipher_spec record MUST
         //  abort the handshake with an "unexpected_message" alert.
         throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "protected change cipher spec received");
         }
      record.fragment.pop_back();
      }

   m_initial_record = false;
   return record;
   }
}
