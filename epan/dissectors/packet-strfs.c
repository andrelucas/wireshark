/* packet-strfs.c
 * Routines for StorageOS DirectFS dissection
 * Copyright 2016, André Lucas <andre.lucas@storageos.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This dissector is for v1 of the StorageOS DirectFS wire protocol. XXX more.
 */

#include <config.h>

#if 0
/* "System" includes used only as needed */
#endif

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <stdlib.h>

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_strfs(void);
void proto_register_strfs(void);

/* Initialize the protocol and registered fields */
static int proto_strfs = -1;
static int hf_strfs_fingerprint = -1;
static int hf_strfs_len = -1;
static int hf_strfs_flags = -1;
static int hf_strfs_flags_ack = -1;
static int hf_strfs_flags_error = -1;
static int hf_strfs_client_xid = -1;
static int hf_strfs_server_xid = -1;
static int hf_strfs_create_sec = -1;
static int hf_strfs_create_nsec = -1;
static int hf_strfs_offset = -1;
static int hf_strfs_request_len = -1;
static int hf_strfs_volid = -1;
static int hf_strfs_type = -1;
static int hf_strfs_version = -1;
static int hf_strfs_payload_len = -1;
static int hf_strfs_reserved0 = -1;
static int hf_strfs_reserved1 = -1;

/* Offsets into the header. */
#define STRFS_OFF_FINGERPRINT 0

/* static expert_field ei_strfs_EXPERTABBREV = EI_INIT; */

/* Global sample preference ("controls" display of numbers) */
/* static gboolean pref_hex = FALSE;*/
/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
/* XXX not standard */
#define STRFS_TCP_PORT 17100
static guint tcp_port_pref = STRFS_TCP_PORT;

/* Initialize the subtree pointers */
static gint ett_strfs = -1;
// static gint ett_strfs_flags = -1;

#define STRFS_ACK 1
#define STRFS_ERROR 2

static const value_string strfs_flags_vals[] = {
    {STRFS_ACK, "ACK"}, {STRFS_ERROR, "ERROR"}, {0, NULL}};

// static const int *flag_fields[] = {&hf_strfs_flags_ack,
// &hf_strfs_flags_error,
//                                    NULL};

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define STRFS_MIN_LENGTH 80

#define STRFS_FINGERPRINT 0x5704a6e0

/* Code to actually dissect the packets */
static int dissect_strfs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         void *data _U_) {
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti; /* , *expert_ti; */
  proto_tree *strfs_tree;
  /* Other misc. local variables. */
  guint offset = 0;
  /* int len = 0; */
  uint32_t strfs_fingerprint;
  uint16_t strfs_len;
  // uint16_t strfs_flags;
  uint64_t strfs_client_xid, strfs_server_xid;
  uint64_t strfs_create_sec, strfs_create_nsec;
  uint64_t strfs_offset;
  uint64_t strfs_request_len;
  uint32_t strfs_volid;
  uint8_t strfs_type;
  uint8_t strfs_version;
  uint16_t strfs_payload_len;
  uint64_t strfs_reserved0, strfs_reserved1;

  /*** HEURISTICS ***/

  /* First, if at all possible, do some heuristics to check if the packet
   * cannot possibly belong to your protocol.  This is especially important
   * for protocols directly on top of TCP or UDP where port collisions are
   * common place (e.g., even though your protocol uses a well known port,
   * someone else may set up, for example, a web server on that port which,
   * if someone analyzed that web server's traffic in Wireshark, would result
   * in Wireshark handing an HTTP packet to your dissector).
   *
   * For example:
   */

  // /* Check that the packet is long enough for it to belong to us. */
  if (tvb_reported_length(tvb) < STRFS_MIN_LENGTH)
    return 0;

  /* Check that there's enough data present to run the heuristics. If there
   * isn't, reject the packet; it will probably be dissected as data and if
   * the user wants it dissected despite it being short they can use the
   * "Decode-As" functionality. If your heuristic needs to look very deep into
   * the packet you may not want to require *all* data to be present, but you
   * should ensure that the heuristic does not access beyond the captured
   * length of the packet regardless. */
  /*  if (tvb_captured_length(tvb) < MAX_NEEDED_FOR_HEURISTICS)
      return 0; */

  /* Fetch some values from the packet header using tvb_get_*(). If these
   * values are not valid/possible in your protocol then return 0 to give
   * some other dissector a chance to dissect it. */
  /* if (TEST_HEURISTICS_FAIL)
    return 0; */

  // Check the fingerprint 32-bit field.
  if (tvb_get_ntohl(tvb, STRFS_OFF_FINGERPRINT) != STRFS_FINGERPRINT)
    return 0;

  /*** COLUMN DATA ***/

  /* There are two normal columns to fill in: the 'Protocol' column which
   * is narrow and generally just contains the constant string 'STRFS',
   * and the 'Info' column which can be much wider and contain misc. summary
   * information (for example, the port number for TCP packets).
   *
   * If you are setting the column to a constant string, use "col_set_str()",
   * as it's more efficient than the other "col_set_XXX()" calls.
   *
   * If
   * - you may be appending to the column later OR
   * - you have constructed the string locally OR
   * - the string was returned from a call to val_to_str()
   * then use "col_add_str()" instead, as that takes a copy of the string.
   *
   * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
   * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
   * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
   * more efficient than "col_add_fstr()".
   *
   * For full details see section 1.4 of README.dissector.
   */

  /* Set the Protocol column to the constant string of STRFS */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "STRFS");

  /* #if 0 */
  /* If you will be fetching any data from the packet before filling in
   * the Info column, clear that column first in case the calls to fetch
   * data from the packet throw an exception so that the Info column doesn't
   * contain data left over from the previous dissector: */
  col_clear(pinfo->cinfo, COL_INFO);
  /* #endif */

  /* col_set_str(pinfo->cinfo, COL_INFO, "XXX Request"); */

  /*** PROTOCOL TREE ***/

  /* Now we will create a sub-tree for our protocol and start adding fields
   * to display under that sub-tree. Most of the time the only functions you
   * will need are proto_tree_add_item() and proto_item_add_subtree().
   *
   * NOTE: The offset and length values in the call to proto_tree_add_item()
   * define what data bytes to highlight in the hex display window when the
   * line in the protocol tree display corresponding to that item is selected.
   *
   * Supplying a length of -1 tells Wireshark to highlight all data from the
   * offset to the end of the packet.
   */

  /* create display subtree for the protocol */
  ti = proto_tree_add_item(tree, proto_strfs, tvb, 0, -1, ENC_NA);

  strfs_tree = proto_item_add_subtree(ti, ett_strfs);

  /* Add an item to the subtree, see section 1.5 of README.dissector for more
   * information. */
  /*  expert_ti = proto_tree_add_item(strfs_tree, hf_strfs_FIELDABBREV, tvb,
     offset,
                                    len, ENC_xxx); */
  strfs_fingerprint = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(strfs_tree, hf_strfs_fingerprint, tvb, offset, 4,
                      strfs_fingerprint);
  offset += 4;

  /* Some fields or situations may require "expert" analysis that can be
   * specifically highlighted. */
  /*  if (TEST_EXPERT_condition) */
  /* value of hf_PROTOABBREV_FIELDABBREV isn't what's expected */
  /*    expert_add_info(pinfo, expert_ti, &ei_PROTOABBREV_EXPERTABBREV); */

  strfs_len = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint(strfs_tree, hf_strfs_len, tvb, offset, 2,
                      (uint32_t)strfs_len);
  offset += 2;

  // strfs_flags = tvb_get_ntohs(tvb, offset);
  // proto_tree_add_bitmask(strfs_tree, tvb, offset, hf_strfs_flags,
  //                        ett_strfs_flags, flag_fields, ENC_BIG_ENDIAN);
  offset += 2;

  strfs_client_xid = tvb_get_ntoh64(tvb, offset);
  proto_tree_add_uint64(strfs_tree, hf_strfs_client_xid, tvb, offset, 8,
                        (uint64_t)strfs_client_xid);
  offset += 8;

  strfs_server_xid = tvb_get_ntoh64(tvb, offset);
  proto_tree_add_uint64(strfs_tree, hf_strfs_server_xid, tvb, offset, 8,
                        (uint64_t)strfs_server_xid);
  offset += 8;

  strfs_create_sec = tvb_get_ntoh64(tvb, offset);
  proto_tree_add_uint64(strfs_tree, hf_strfs_create_sec, tvb, offset, 8,
                        (uint64_t)strfs_create_sec);
  offset += 8;

  strfs_create_nsec = tvb_get_ntoh64(tvb, offset);
  proto_tree_add_uint64(strfs_tree, hf_strfs_create_nsec, tvb, offset, 8,
                        (uint64_t)strfs_create_nsec);
  offset += 8;

  strfs_offset = tvb_get_ntoh64(tvb, offset);
  proto_tree_add_uint64(strfs_tree, hf_strfs_offset, tvb, offset, 8,
                        (uint64_t)strfs_offset);
  offset += 8;

  strfs_request_len = tvb_get_ntoh64(tvb, offset);
  proto_tree_add_uint64(strfs_tree, hf_strfs_request_len, tvb, offset, 8,
                        (uint64_t)strfs_request_len);
  offset += 8;

  strfs_volid = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(strfs_tree, hf_strfs_volid, tvb, offset, 4, strfs_volid);
  offset += 4;

  strfs_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(strfs_tree, hf_strfs_type, tvb, offset, 1, ENC_NA);
  offset += 1;

  strfs_version = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(strfs_tree, hf_strfs_version, tvb, offset, 1, ENC_NA);
  offset += 1;

  strfs_payload_len = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(strfs_tree, hf_strfs_payload_len, tvb, offset, 2, ENC_NA);
  offset += 2;

  strfs_reserved0 = tvb_get_ntoh64(tvb, offset);
  proto_tree_add_uint64(strfs_tree, hf_strfs_reserved0, tvb, offset, 8,
                        (uint64_t)strfs_reserved0);
  offset += 8;

  strfs_reserved1 = tvb_get_ntoh64(tvb, offset);
  proto_tree_add_uint64(strfs_tree, hf_strfs_reserved1, tvb, offset, 8,
                        (uint64_t)strfs_reserved1);
  offset += 8;

  /* Continue adding tree items to process the packet here... */

  /* If this protocol has a sub-dissector call it here, see section 1.8 of
   * README.dissector for more information. */

  /* Return the amount of data this dissector was able to dissect (which may
   * or may not be the total captured packet as we return here). */
  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void proto_register_strfs(void) {
  module_t *strfs_module;
  // expert_module_t *expert_strfs;

  /* Setup list of header fields  See Section 1.5 of README.dissector for
   * details. */
  static hf_register_info hf[] = {
      {&hf_strfs_fingerprint,
       {"Fingerprint", "strfs.fingerprint", FT_UINT32, BASE_HEX, NULL, 0x0,
        "strfs protocol locator", HFILL}},

      {&hf_strfs_len,
       {"Packet length", "strfs.len", FT_UINT16, BASE_DEC, NULL, 0x0,
        "strfs packet length", HFILL}},

      {&hf_strfs_flags,
       {"Flags", "strfs.flags", FT_UINT16, BASE_HEX, VALS(strfs_flags_vals),
        0x0, "strfs flags", HFILL}},

      {&hf_strfs_flags_ack,
       {"ACK", "strfs.flags.ack", FT_BOOLEAN, BASE_HEX, NULL, 0, NULL, HFILL}},

      {&hf_strfs_flags_error,
       {"ERROR", "strfs.flags.error", FT_BOOLEAN, BASE_HEX, NULL, 0, NULL,
        HFILL}},

      {&hf_strfs_client_xid,
       {"Client transaction ID", "strfs.client_xid", FT_UINT64, BASE_HEX, NULL,
        0x0, "strfs client transaction ID", HFILL}},

      {&hf_strfs_server_xid,
       {"Server transaction ID", "strfs.server_xid", FT_UINT64, BASE_HEX, NULL,
        0x0, "strfs server transaction ID", HFILL}},

      {&hf_strfs_create_sec,
       {"Transaction create time seconds", "strfs.create_sec", FT_UINT64,
        BASE_DEC, NULL, 0x0, "strfs transaction create time second value",
        HFILL}},

      {&hf_strfs_create_nsec,
       {"Transaction create time nanoseconds", "strfs.create_nsec", FT_UINT64,
        BASE_DEC, NULL, 0x0, "strfs transaction create time nanosecond value",
        HFILL}},

      {&hf_strfs_offset,
       {"Transaction offset", "strfs.offset", FT_UINT64, BASE_HEX, NULL, 0x0,
        "strfs transaction file offset", HFILL}},

      {&hf_strfs_request_len,
       {"Transaction request length", "strfs.request_len", FT_UINT64, BASE_DEC,
        NULL, 0x0, "strfs transaction request length", HFILL}},

      {&hf_strfs_volid,
       {"Transaction volume ID", "strfs.volume_id", FT_UINT32, BASE_DEC, NULL,
        0x0, "strfs request volume ID", HFILL}},

      /* XXX type needs decoded */
      {&hf_strfs_type,
       {"Transaction type", "strfs.type", FT_UINT8, BASE_DEC, NULL, 0x0,
        "strfs protocol request type", HFILL}},

      {&hf_strfs_version,
       {"Protocol version", "strfs.version", FT_UINT8, BASE_DEC, NULL, 0x0,
        "strfs protocol version", HFILL}},

      {&hf_strfs_payload_len,
       {"Protocol payload length", "strfs.payload_len", FT_UINT16, BASE_DEC,
        NULL, 0x0, "strfs protocol version", HFILL}},

      {&hf_strfs_reserved0,
       {"Reserved field 0", "strfs.reserved0", FT_UINT64, BASE_HEX, NULL, 0x0,
        "strfs reserved0 field", HFILL}},

      {&hf_strfs_reserved1,
       {"Reserved field 1", "strfs.reserved1", FT_UINT64, BASE_HEX, NULL, 0x0,
        "strfs reserved1 field", HFILL}},
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {&ett_strfs};

  /* Register the protocol name and description */
  proto_strfs = proto_register_protocol("StorageOS DirectFS wire protocol",
                                        "StorageOS DirectFS", "strfs");

  /* Required function calls to register the header fields and subtrees */
  proto_register_field_array(proto_strfs, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("strfs", dissect_strfs, proto_strfs);
  strfs_module = prefs_register_protocol(proto_strfs, proto_reg_handoff_strfs);
  prefs_register_uint_preference(strfs_module, "tcp.port", "STRFS TCP Port",
                                 " STRFS TCP port if other than the default",
                                 10, &tcp_port_pref);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void proto_reg_handoff_strfs(void) {
  static gboolean initialized = FALSE;
  static dissector_handle_t strfs_handle;
  static int current_port;

  if (!initialized) {
    /* Use create_dissector_handle() to indicate that
     * dissect_strfs() returns the number of bytes it dissected (or 0
     * if it thinks the packet does not belong to STRFS).
     */
    strfs_handle = create_dissector_handle(dissect_strfs, proto_strfs);
    initialized = TRUE;

  } else {
    /* If you perform registration functions which are dependent upon
     * prefs then you should de-register everything which was associated
     * with the previous settings and re-register using the new prefs
     * settings here. In general this means you need to keep track of
     * the strfs_handle and the value the preference had at the time
     * you registered.  The strfs_handle value and the value of the
     * preference can be saved using local statics in this
     * function (proto_reg_handoff).
     */
    dissector_delete_uint("tcp.port", current_port, strfs_handle);
  }

  current_port = tcp_port_pref;

  dissector_add_uint("tcp.port", current_port, strfs_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
