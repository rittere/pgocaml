(* PG'OCaml is a set of OCaml bindings for the PostgreSQL database.
 *
 * PG'OCaml - type safe interface to PostgreSQL.
 * Copyright (C) 2005-2009 Richard Jones and other authors.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *)

module TLS_thread = struct
  type 'a t = 'a
  let return x = x
  let (>>=) v f =  f v
  let fail = raise
  let catch f fexn = try f () with e -> fexn e

  exception IllegalParameters of string

  type in_channel = Netchannels.in_obj_channel
  type out_channel = Netchannels.out_obj_channel
  (*   type tls_endpoint_t =  Netsys_crypto_types.tls_endpoint option *)
  let open_connection addr =
    let (ic, oc) = Unix.open_connection addr in
    new Netchannels.input_channel ic, new Netchannels.output_channel oc
  let output_char oc =  oc#output_char
  let output_string oc = oc#output_string
  let output_binary_int oc n =
    let nBytes = Netnumber.BE.int4_as_bytes (Netnumber.int4_of_int n) in
    oc#output_bytes nBytes
  let flush oc = oc#flush()
  let input_char ic = ic#input_char()
  let input_binary_int ic =
    let nBytes = Bytes.create 4 in
    ic#really_input nBytes 0 4;
    Netnumber.int_of_int4 (Netnumber.BE.read_int4 nBytes 0)
  let really_input ic = ic#really_input 
  let close_in ic = ic#close_in()

  let tls_init ~peer_name  ~verify ~system_trust ~sslcert ~sslkey ~sslpassword ~sslcertmode ~sslrootcert ~sslcrl ~peer_auth ~ichan ~chan  =
    let trust =
      match sslrootcert with
      | None ->
         if not system_trust && peer_auth = `Required then
           raise (IllegalParameters "certificate authority file not found and \"system\" not specified")
         else []
      | Some "system" -> []
      | Some sslrootcert -> [`PEM_file sslrootcert] in
    let revoke =
      match sslcrl with
      | None -> []
      | Some sslcrl -> [`PEM_file sslcrl ] in
    let keys =
      match sslcert, sslkey with
      | None, _ | _, None -> []
      | Some sslcert, Some sslkey ->
         [(`PEM_file sslcert, `PEM_file sslkey, sslpassword)] in
    let keys =
      if sslcertmode = `Disable then []
      else if sslcertmode = `Require && keys = [] then
        raise (IllegalParameters "client authentication required but no keys provided")
      else keys in
    Nettls_gnutls.init();
    let tls = Netsys_crypto.current_tls() in
    let tls_config = Netsys_tls.create_x509_config ~verify ~system_trust ~trust  ~revoke ~keys ~peer_auth tls in
    let tls_ch =
      new Netchannels_crypto.tls_layer
      ~role:`Client
      ~rd:(ichan :> Netchannels.raw_in_channel)
      ~wr:(chan :> Netchannels.raw_out_channel)
        ~peer_name
        tls_config in
    (try 
       tls_ch # flush()(* This enforces the TLS handshake *)
     with
     |  (Netsys_types.TLS_error error) as exn ->  
         if error <> "NETTLS_VERIFICATION_FAILED" || peer_auth = `Required then 
           raise exn);
    let ic = Netchannels.lift_in (`Raw (tls_ch :> Netchannels.raw_in_channel)) in
    let oc = Netchannels.lift_out (`Raw (tls_ch :> Netchannels.raw_out_channel)) in
    (ic, oc)
end

module M = PGOCaml_generic.Make (TLS_thread)

include M
