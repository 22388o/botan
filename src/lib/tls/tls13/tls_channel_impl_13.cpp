/*
* TLS Channel - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl_13.h>

#include <botan/hash.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/tls_messages.h>

namespace {
bool is_closure_alert(const Botan::TLS::Alert& alert)
   {
   return alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY
          || alert.type() == Botan::TLS::Alert::USER_CANCELED;
   }

bool is_error_alert(const Botan::TLS::Alert& alert)
   {
   // In TLS 1.3 all alerts except for closure alerts are considered error alerts.
   // (RFC 8446 6.)
   return !is_closure_alert(alert);
   }
}

namespace Botan::TLS {

Channel_Impl_13::Channel_Impl_13(Callbacks& callbacks,
                                 Session_Manager& session_manager,
                                 RandomNumberGenerator& rng,
                                 const Policy& policy,
                                 bool is_server,
                                 size_t) :
   m_side(is_server ? Connection_Side::SERVER : Connection_Side::CLIENT),
   m_callbacks(callbacks),
   m_session_manager(session_manager),
   m_rng(rng),
   m_policy(policy),
   m_record_layer(m_side),
   m_handshake_layer(m_side),
   m_can_read(true),
   m_can_write(true)
   {
   }

Channel_Impl_13::~Channel_Impl_13() = default;

size_t Channel_Impl_13::received_data(const uint8_t input[], size_t input_size)
   {
   // RFC 8446 6.1
   //    Any data received after a closure alert has been received MUST be ignored.
   if(!m_can_read)
      { return 0; }

   try
      {
      m_record_layer.copy_data(std::vector(input, input+input_size));

      while(true)
         {
         auto result = m_record_layer.next_record(m_cipher_state.get());

         if(std::holds_alternative<BytesNeeded>(result))
            { return std::get<BytesNeeded>(result); }

         auto record = std::get<Record>(result);
         if(record.type == HANDSHAKE)
            {
            m_handshake_layer.copy_data(unlock(record.fragment));  // TODO: record fragment should be an ordinary std::vector

            while(true)
               {
               // TODO: BytesNeeded is not needed here, hence we could make `next_message` return an optional
               auto handshake_msg = m_handshake_layer.next_message(policy(), m_transcript_hash);

               if(std::holds_alternative<BytesNeeded>(handshake_msg))
                  { break; }

               process_handshake_msg(std::move(std::get<Handshake_Message_13>(handshake_msg)));
               }
            }
         else if(record.type == CHANGE_CIPHER_SPEC)
            {
            // RFC 8446 5.
            //    An implementation may receive an unencrypted record of type change_cipher_spec
            //    [...]
            //    at any time after the first ClientHello message has been sent or received
            //    and before the peer's Finished message has been received
            //    TODO: Unexpected_Message otherwise
            //    [...]
            //    and MUST simply drop it without further processing.
            // TODO: Send CCS in response / middlebox compatibility mode to be defined via the policy
            }
         else if(record.type == APPLICATION_DATA)
            {
            BOTAN_ASSERT(record.seq_no.has_value(), "decrypted application traffic had a sequence number");
            callbacks().tls_record_received(record.seq_no.value(), record.fragment.data(), record.fragment.size());
            }
         else if(record.type == ALERT)
            {
            process_alert(record.fragment);
            }
         else
            { throw Unexpected_Message("Unexpected record type " + std::to_string(record.type) + " from counterparty"); }
         }
      }
   catch(TLS_Exception& e)
      {
      send_fatal_alert(e.type());
      throw;
      }
   catch(Invalid_Authentication_Tag&)
      {
      // RFC 8446 5.2
      //    If the decryption fails, the receiver MUST terminate the connection
      //    with a "bad_record_mac" alert.
      send_fatal_alert(Alert::BAD_RECORD_MAC);
      throw;
      }
   catch(Decoding_Error&)
      {
      send_fatal_alert(Alert::DECODE_ERROR);
      throw;
      }
   catch(...)
      {
      send_fatal_alert(Alert::INTERNAL_ERROR);
      throw;
      }
   }

void Channel_Impl_13::send_handshake_message(const Handshake_Message_13_Ref message)
   {
   send_record(Record_Type::HANDSHAKE, m_handshake_layer.prepare_message(message, m_transcript_hash));
   }

void Channel_Impl_13::send(const uint8_t buf[], size_t buf_size)
   {
   if(!is_active())
      { throw Invalid_State("Data cannot be sent on inactive TLS connection"); }

   send_record(Record_Type::APPLICATION_DATA, {buf, buf+buf_size});
   }

void Channel_Impl_13::send_alert(const Alert& alert)
   {
   if(alert.is_valid() && m_can_write)
      {
      try
         {
         send_record(Record_Type::ALERT, alert.serialize());
         }
      catch(...) { /* swallow it */ }
      }

   // Note: In TLS 1.3 sending a CLOSE_NOTIFY must not immediately lead to closing the reading end.
   // RFC 8446 6.1
   //    Each party MUST send a "close_notify" alert before closing its write
   //    side of the connection, unless it has already sent some error alert.
   //    This does not have any effect on its read side of the connection.
   if(is_closure_alert(alert))
      {
      m_can_write = false;
      m_cipher_state->clear_write_keys();
      }

   if(is_error_alert(alert))
      { shutdown(); }
   }

bool Channel_Impl_13::is_active() const
   {
   return
      m_cipher_state != nullptr && m_cipher_state->can_encrypt_application_traffic() // handshake done
      && m_can_write;  // close() hasn't been called
   }

SymmetricKey Channel_Impl_13::key_material_export(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   BOTAN_UNUSED(label, context, length);
   throw Not_Implemented("key material export is not implemented");
   }

void Channel_Impl_13::send_record(uint8_t record_type, const std::vector<uint8_t>& record)
   {
   BOTAN_STATE_CHECK(m_can_write);
   const auto to_write = m_record_layer.prepare_records(static_cast<Record_Type>(record_type),
                         record, m_cipher_state.get());
   callbacks().tls_emit_data(to_write.data(), to_write.size());
   }

void Channel_Impl_13::process_alert(const secure_vector<uint8_t>& record)
   {
   Alert alert(record);

   if(is_closure_alert(alert))
      {
      m_can_read = false;
      m_cipher_state->clear_read_keys();
      }

   if(is_error_alert(alert))
      { shutdown(); }

   callbacks().tls_alert(alert);
   }

void Channel_Impl_13::shutdown()
   {
   // RFC 8446 6.2
   //    Upon transmission or receipt of a fatal alert message, both
   //    parties MUST immediately close the connection.
   m_can_read = false;
   m_can_write = false;
   m_cipher_state.reset();
   }

}
