/**
 * @file hccapx_serializer.c
 * @author risinek
 * @brief Implements HCCAPX serializer
 */

 #include "hccapx_serializer.h"

 #include <stdint.h>
 #include <string.h>
 #define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
 #include "esp_log.h"
 #include "esp_err.h"
 #include "frame_analyzer.h"
 #include "frame_analyzer_types.h"
 #include "frame_analyzer_parser.h"
 #include "lwip/inet.h"  // ✅ Required for ntohs()
 
 // Constants based on HCCAPX reference
 #define HCCAPX_SIGNATURE 0x58504348
 #define HCCAPX_VERSION 4
 #define HCCAPX_KEYVER_WPA 1
 #define HCCAPX_KEYVER_WPA2 2
 #define HCCAPX_MAX_EAPOL_SIZE 256
 
 static char *TAG = "hccapx_serializer";
 
 static hccapx_t hccapx = {
     .signature = HCCAPX_SIGNATURE,
     .version = HCCAPX_VERSION,
     .message_pair = 255,
     .keyver = HCCAPX_KEYVER_WPA2
 };
 
 static unsigned message_ap = 0;
 static unsigned message_sta = 0;
 static unsigned eapol_source = 0;
 
 static bool is_array_zero(uint8_t *array, unsigned size) {
     for (unsigned i = 0; i < size; i++) {
         if (array[i] != 0) {
             return false;
         }
     }
     return true;
 }
 
 void hccapx_serializer_init(const uint8_t *ssid, unsigned size) {
     hccapx.essid_len = size;
     memcpy(hccapx.essid, ssid, size);
     hccapx.message_pair = 255;
 }
 
 hccapx_t *hccapx_serializer_get() {
     if (hccapx.message_pair == 255) {
         return NULL;
     }
     return &hccapx;
 }
 
 static unsigned save_eapol(eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
     unsigned eapol_len = sizeof(eapol_packet_header_t) + ntohs(eapol_packet->header.packet_body_length);
     if (eapol_len > HCCAPX_MAX_EAPOL_SIZE) {
         ESP_LOGW(TAG, "EAPoL is too long (%u/%u)", eapol_len, HCCAPX_MAX_EAPOL_SIZE);
         return 1;
     }
     hccapx.eapol_len = eapol_len;
     memcpy(hccapx.eapol, eapol_packet, eapol_len);
     memcpy(hccapx.keymic, eapol_key_packet->key_mic, 16);
     memset(&hccapx.eapol[81], 0x0, 16);  // Clear MIC for hashcat
     return 0;
 }
 
 static void ap_message_m1(eapol_key_packet_t *eapol_key_packet) {
     ESP_LOGD(TAG, "From AP M1");
     message_ap = 1;
     memcpy(hccapx.nonce_ap, eapol_key_packet->key_nonce, 32);
 }
 
 static void ap_message_m3(eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
     ESP_LOGD(TAG, "From AP M3");
     message_ap = 3;
     if (message_ap == 0) {
         memcpy(hccapx.nonce_ap, eapol_key_packet->key_nonce, 32);
     }
     if (eapol_source == 2) {
         hccapx.message_pair = 2;
         return;
     }
     if (save_eapol(eapol_packet, eapol_key_packet) != 0) {
         return;
     }
     eapol_source = 3;
     if (message_sta == 2) {
         hccapx.message_pair = 3;
     }
 }
 
 static void ap_message(data_frame_t *frame, eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
     if ((!is_array_zero(hccapx.mac_sta, 6)) &&
         (memcmp(frame->mac_header.addr1, hccapx.mac_sta, 6) != 0)) {
         ESP_LOGE(TAG, "Different STA");
         return;
     }
     if (message_ap == 0) {
         memcpy(hccapx.mac_ap, frame->mac_header.addr2, 6);
     }
     if (is_array_zero(eapol_key_packet->key_mic, 16)) {
         ap_message_m1(eapol_key_packet);
     } else {
         ap_message_m3(eapol_packet, eapol_key_packet);
     }
 }
 
 static void sta_message_m2(eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
     ESP_LOGD(TAG, "From STA M2");
     message_sta = 2;
     memcpy(hccapx.nonce_sta, eapol_key_packet->key_nonce, 32);
     if (save_eapol(eapol_packet, eapol_key_packet) != 0) {
         return;
     }
     eapol_source = 2;
     if (message_ap == 1) {
         hccapx.message_pair = 0;
     }
 }
 
 static void sta_message_m4(eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
     ESP_LOGD(TAG, "From STA M4");
     if ((message_sta == 2) && (eapol_source != 0)) {
         ESP_LOGD(TAG, "Already have M2, not worth");
         return;
     }
     if (message_ap == 0) {
         ESP_LOGE(TAG, "Not enough handshake messages received.");
         return;
     }
     if (eapol_source == 3) {
         hccapx.message_pair = 4;
         return;
     }
     if (save_eapol(eapol_packet, eapol_key_packet) != 0) {
         return;
     }
     eapol_source = 4;
     if (message_ap == 1) {
         hccapx.message_pair = 1;
     }
     if (message_ap == 3) {
         hccapx.message_pair = 5;
     }
 }
 
 static void sta_message(data_frame_t *frame, eapol_packet_t *eapol_packet, eapol_key_packet_t *eapol_key_packet) {
     if (is_array_zero(hccapx.mac_sta, 6)) {
         memcpy(hccapx.mac_sta, frame->mac_header.addr2, 6);
     } else if (memcmp(frame->mac_header.addr2, hccapx.mac_sta, 6) != 0) {
         ESP_LOGE(TAG, "Different STA");
         return;
     }
     if (!is_array_zero(eapol_key_packet->key_nonce, 16)) {
         sta_message_m2(eapol_packet, eapol_key_packet);
     } else {
         sta_message_m4(eapol_packet, eapol_key_packet);
     }
 }
 
 void hccapx_serializer_add_frame(data_frame_t *frame) {
     eapol_packet_t *eapol_packet = parse_eapol_packet(frame);
     eapol_key_packet_t *eapol_key_packet = parse_eapol_key_packet(eapol_packet);
     if (memcmp(frame->mac_header.addr2, frame->mac_header.addr3, 6) == 0) {
         ap_message(frame, eapol_packet, eapol_key_packet);
     } else if (memcmp(frame->mac_header.addr1, frame->mac_header.addr3, 6) == 0) {
         sta_message(frame, eapol_packet, eapol_key_packet);
     } else {
         ESP_LOGE(TAG, "Unknown frame format. BSSID is not source nor destination.");
     }
 }
 