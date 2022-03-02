/*
* TLS Client - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/internal/tls_client_impl_13.h>

#include <botan/credentials_manager.h>
#include <botan/hash.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/tls_client.h>
#include <botan/tls_messages.h>

#include <iterator>

namespace Botan::TLS {

Client_Impl_13::Client_Impl_13(Callbacks& callbacks,
                               Session_Manager& session_manager,
                               Credentials_Manager& creds,
                               const Policy& policy,
                               RandomNumberGenerator& rng,
                               const Server_Information& info,
                               const Protocol_Version& offer_version,
                               const std::vector<std::string>& next_protocols,
                               size_t io_buf_sz) :
   Channel_Impl_13(callbacks, session_manager, rng, policy, false, io_buf_sz),
   m_creds(creds),
   m_info(info)
   {
   BOTAN_UNUSED(m_creds, offer_version); // TODO: fixme

   Client_Hello::Settings client_settings(TLS::Protocol_Version::TLS_V13, m_info.hostname());
   send_handshake_message(m_handshake_state.sent(Client_Hello_13(
                             policy,
                             callbacks,
                             rng,
                             std::vector<uint8_t>(),
                             client_settings,
                             next_protocols)));

   m_transitions.set_expected_next({SERVER_HELLO, HELLO_RETRY_REQUEST});
   }

void Client_Impl_13::process_handshake_msg(Handshake_Message_13 message)
   {
   std::visit([&](auto msg)
      {
      m_transitions.confirm_transition_to(msg.get().type());
      handle(msg.get());
      }, m_handshake_state.received(std::move(message)));
   }

std::vector<Handshake_Type> Client_Impl_13::expected_post_handshake_messages() const
   {
   BOTAN_STATE_CHECK(is_active());
   // TODO: This list may contain CERTIFICATE_REQUEST iff the client hello advertised
   //       support for post-handshake authentication via the post_handshake_auth
   //       extension. (RFC 8446 4.6.2)
   return { NEW_SESSION_TICKET, KEY_UPDATE };
   }

namespace  {
// validate Server_Hello and Hello_Retry_Request
void validate_server_hello_ish(const Client_Hello_13& ch, const Server_Hello_13& sh)
   {
   // RFC 8446 4.1.3
   //    A client which receives a legacy_session_id_echo field that does not match what
   //    it sent in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
   if(ch.session_id() != sh.session_id())
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "echoed session id did not match");
      }

   // RFC 8446 4.1.3
   //    A client which receives a cipher suite that was not offered MUST abort the handshake
   //    with an "illegal_parameter" alert.
   if(!ch.offered_suite(sh.ciphersuite()))
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Ciphersuite was not offered");
      }

   // RFC 8446 4.2.1
   //    If the "supported_versions" extension in the ServerHello contains a
   //    version not offered by the client or contains a version prior to
   //    TLS 1.3, the client MUST abort the handshake with an "illegal_parameter" alert.
   BOTAN_ASSERT_NOMSG(ch.extensions().has<Supported_Versions>());
   if(!ch.extensions().get<Supported_Versions>()->supports(sh.selected_version()))
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Protocol_Version was not offered");
      }

   // RFC 8446 4.1.4.
   //    A HelloRetryRequest MUST NOT contain any
   //    extensions that were not first offered by the client in its
   //    ClientHello, with the exception of optionally the "cookie".
   for(auto ext_type : sh.extensions().extension_types())
      {
      if(ext_type != TLSEXT_COOKIE && ch.extensions().extension_types().count(ext_type) == 0)
         {
         throw TLS_Exception(Alert::UNSUPPORTED_EXTENSION, "extension was not offered");
         }
      }
   }
}

void Client_Impl_13::handle(const Server_Hello_13& sh)
   {
   // Note: Basic checks (that do not require contextual information) were already
   //       performed during the construction of the Server_Hello_13 object.

   const auto& ch = m_handshake_state.client_hello();

   // TODO: have another close look at this once we start implementing
   //       protocol downgrade!
   if(auto requested = sh.random_signals_downgrade())
      {
      if(requested.value() == Protocol_Version::TLS_V11)
         { throw TLS_Exception(Alert::PROTOCOL_VERSION, "TLS 1.1 is not supported"); }
      if(requested.value() == Protocol_Version::TLS_V12)
         { throw Not_Implemented("downgrade is nyi"); }
      }

   validate_server_hello_ish(ch, sh);

   if(m_handshake_state.has_hello_retry_request())
      {
      const auto& hrr = m_handshake_state.hello_retry_request();

      // RFC 8446 4.1.4
      //    Upon receiving the ServerHello, clients MUST check that the cipher suite
      //    supplied in the ServerHello is the same as that in the HelloRetryRequest
      //    and otherwise abort the handshake with an "illegal_parameter" alert.
      if(hrr.ciphersuite() != sh.ciphersuite())
         {
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "server changed its chosen ciphersuite");
         }

      // RFC 8446 4.1.4
      //    The value of selected_version in the HelloRetryRequest "supported_versions"
      //    extension MUST be retained in the ServerHello, and a client MUST abort the
      //    handshake with an "illegal_parameter" alert if the value changes.
      if(hrr.selected_version() != sh.selected_version())
         {
         throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "server changed its chosen protocol version");
         }
      }

   auto cipher = Ciphersuite::by_id(sh.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher.has_value());  // should work, since we offered this suite

   if(!sh.extensions().has<Key_Share>())
      {
      throw Not_Implemented("PSK mode (without key agreement) is NYI");
      }

   // TODO: this is assuming a standard handshake without any PSK mode!
   BOTAN_ASSERT_NOMSG(ch.extensions().has<Key_Share>());
   auto my_keyshare = ch.extensions().get<Key_Share>();
   auto shared_secret = my_keyshare->exchange(sh.extensions().get<Key_Share>(), policy(), callbacks(), rng());

   m_transcript_hash.set_algorithm(cipher.value().prf_algo());

   m_cipher_state = Cipher_State::init_with_server_hello(m_side,
                    std::move(shared_secret),
                    cipher.value(),
                    m_transcript_hash.current());

   callbacks().tls_examine_extensions(m_handshake_state.server_hello().extensions(), SERVER);

   m_transitions.set_expected_next(ENCRYPTED_EXTENSIONS);
   }

void Client_Impl_13::handle(const Hello_Retry_Request& hrr)
   {
   // Note: Basic checks (that do not require contextual information) were already
   //       performed during the construction of the Hello_Retry_Request object as
   //       a subclass of Server_Hello_13.

   auto& ch = m_handshake_state.client_hello();

   validate_server_hello_ish(ch, hrr);

   auto cipher = Ciphersuite::by_id(hrr.ciphersuite());
   BOTAN_ASSERT_NOMSG(cipher.has_value());  // should work, since we offered this suite

   m_transcript_hash = Transcript_Hash_State::recreate_after_hello_retry_request(cipher.value().prf_algo(), m_transcript_hash);

   ch.retry(hrr, callbacks(), rng());

   send_handshake_message(ch);

   // RFC 8446 4.1.4
   //    If a client receives a second HelloRetryRequest in the same connection [...],
   //    it MUST abort the handshake with an "unexpected_message" alert.
   m_transitions.set_expected_next(SERVER_HELLO);
   }

void Client_Impl_13::handle(const Encrypted_Extensions& encrypted_extensions_msg)
   {
   // TODO: check all extensions are allowed and expected

   // Note: As per RFC 6066 3. we can check for an empty SNI extensions to
   // determine if the server used the SNI we sent here.

   callbacks().tls_examine_extensions(encrypted_extensions_msg.extensions(), SERVER);

   bool psk_mode = false;  // TODO
   if(psk_mode)
      {
      m_transitions.set_expected_next(FINISHED);
      }
   else
      {
      m_transitions.set_expected_next({CERTIFICATE, CERTIFICATE_REQUEST});
      }
   }

void Client_Impl_13::handle(const Certificate_13& certificate_msg)
   {
   certificate_msg.validate_extensions(m_handshake_state.client_hello().extensions());
   const auto& server_certs = certificate_msg.cert_chain();

   // RFC 8446 4.4.2.4
   //    If the server supplies an empty Certificate message, the client
   //    MUST abort the handshake with a "decode_error" alert.
   if(server_certs.empty())
      { throw TLS_Exception(Alert::DECODE_ERROR, "Client: No certificates sent by server"); }

   auto trusted_CAs = m_creds.trusted_certificate_authorities("tls-client", m_info.hostname());

   std::vector<X509_Certificate> certs;
   std::transform(server_certs.cbegin(), server_certs.cend(), std::back_inserter(certs),
   [](const auto& entry) { return entry.certificate; });

   callbacks().tls_verify_cert_chain(certs,
                                     {},  // TODO: Support OCSP stapling via RFC8446 4.4.2.1
                                     trusted_CAs,
                                     Usage_Type::TLS_SERVER_AUTH,
                                     m_info.hostname(),
                                     policy());

   m_transitions.set_expected_next(CERTIFICATE_VERIFY);
   }

void Client_Impl_13::handle(const Certificate_Verify_13& certificate_verify_msg)
   {
   bool sig_valid = certificate_verify_msg.verify(
                       m_handshake_state.certificate().cert_chain().front().certificate,
                       m_handshake_state.client_hello().signature_schemes(),
                       callbacks(),
                       m_transcript_hash.previous());

   if(!sig_valid)
      { throw TLS_Exception(Alert::DECRYPT_ERROR, "Server certificate verification failed"); }

   m_transitions.set_expected_next(FINISHED);
   }

void Client_Impl_13::handle(const Finished_13& finished_msg)
   {
   // RFC 8446 4.4.4
   //    Recipients of Finished messages MUST verify that the contents are
   //    correct and if incorrect MUST terminate the connection with a
   //    "decrypt_error" alert.
   if(!finished_msg.verify(m_cipher_state.get(),
                           m_transcript_hash.previous()))
      { throw TLS_Exception(Alert::DECRYPT_ERROR, "Finished message didn't verify"); }

   // send client finished handshake message (still using handshake traffic secrets)
   send_handshake_message(m_handshake_state.sent(Finished_13(m_cipher_state.get(),
                          m_transcript_hash.current())));

   // derives the application traffic secrets and _replaces_ the handshake traffic secrets
   // Note: this MUST happen AFTER the client finished message was sent!
   m_cipher_state->advance_with_server_finished(m_transcript_hash.previous());
   m_cipher_state->advance_with_client_finished(m_transcript_hash.current());

   // TODO: save session and invoke tls_session_established callback

   callbacks().tls_session_activated();

   m_transitions.set_expected_next(expected_post_handshake_messages());
   }

void TLS::Client_Impl_13::handle(const New_Session_Ticket_13&)
   {
   m_transitions.set_expected_next(expected_post_handshake_messages());
   }

}
