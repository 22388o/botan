/*
* TLS Channel - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IMPL_13_H_
#define BOTAN_TLS_CHANNEL_IMPL_13_H_

#include <botan/internal/tls_channel_impl.h>
#include <botan/internal/tls_record_layer_13.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_transcript_hash_13.h>

namespace Botan::TLS {

/**
* Generic interface for TLSv.12 endpoint
*/
class Channel_Impl_13 : public Channel_Impl
   {
   public:
      /**
      * Set up a new TLS 1.3 session
      *
      * @param callbacks contains a set of callback function references
      *        required by the TLS endpoint.
      * @param session_manager manages session state
      * @param rng a random number generator
      * @param policy specifies other connection policy information
      * @param is_server whether this is a server session or not
      */
      explicit Channel_Impl_13(Callbacks& callbacks,
                               Session_Manager& session_manager,
                               RandomNumberGenerator& rng,
                               const Policy& policy,
                               bool is_server,
                               size_t /* unused */);

      explicit Channel_Impl_13(const Channel_Impl_13&) = delete;

      Channel_Impl_13& operator=(const Channel_Impl_13&) = delete;

      virtual ~Channel_Impl_13();

      size_t received_data(const uint8_t buf[], size_t buf_size) override;

      /**
      * Inject plaintext intended for counterparty
      * Throws an exception if is_active() is false
      */
      void send(const uint8_t buf[], size_t buf_size) override;

      /**
      * Send a TLS alert message. If the alert is fatal, the internal
      * state (keys, etc) will be reset.
      * @param alert the Alert to send
      */
      void send_alert(const Alert& alert) override;

      /**
      * @return true iff the connection is active for sending application data
      *
      * Note that the connection is active until the application has called
      * `close()`, even if a CLOSE_NOTIFY has been received from the peer.
      */
      bool is_active() const override;

      /**
      * @return true iff the connection has been closed, i.e. CLOSE_NOTIFY
      * has been received from the peer.
      */
      bool is_closed() const override { return !m_can_read; }

      /**
      * Key material export (RFC 5705)
      * @param label a disambiguating label string
      * @param context a per-association context value
      * @param length the length of the desired key in bytes
      * @return key of length bytes
      */
      SymmetricKey key_material_export(const std::string& label,
                                       const std::string& context,
                                       size_t length) const override;

      /**
      * Attempt to renegotiate the session
      */
      void renegotiate(bool/* unused */) override
         {
         throw Botan::Invalid_Argument("renegotiation is not allowed in TLS 1.3");
         }

      /**
      * @return true iff the counterparty supports the secure
      * renegotiation extensions.
      */
      bool secure_renegotiation_supported() const override
         {
         // No renegotiation supported in TLS 1.3
         return false;
         }

      /**
      * Perform a handshake timeout check. This does nothing unless
      * this is a DTLS channel with a pending handshake state, in
      * which case we check for timeout and potentially retransmit
      * handshake packets.
      *
      * In the TLS 1.3 implementation, this always returns false.
      */
      bool timeout_check() override { return false; }

   protected:
      virtual void process_handshake_msg(Handshake_Message_13 msg) = 0;
      void send_handshake_message(const Handshake_Message_13_Ref message);

      Callbacks& callbacks() const { return m_callbacks; }
      Session_Manager& session_manager() { return m_session_manager; }
      RandomNumberGenerator& rng() { return m_rng; }
      const Policy& policy() const { return m_policy; }

   private:
      void send_record(uint8_t record_type, const std::vector<uint8_t>& record);

      void process_alert(const secure_vector<uint8_t>& record);

      /**
       * Terminate the connection (on sending or receiving an error alert) and
       * clear secrets
       */
      void shutdown();

   protected:
      const Connection_Side m_side;
      Transcript_Hash_State m_transcript_hash;
      std::unique_ptr<Cipher_State> m_cipher_state;

   private:
      /* callbacks */
      Callbacks& m_callbacks;

      /* external state */
      Session_Manager& m_session_manager;
      RandomNumberGenerator& m_rng;
      const Policy& m_policy;

      /* handshake state */
      Record_Layer m_record_layer;
      Handshake_Layer m_handshake_layer;

      bool m_can_read;
      bool m_can_write;
   };
}

#endif
