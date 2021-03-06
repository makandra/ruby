=begin
= $RCSfile$ -- Ruby-space definitions that completes C-space funcs for SSL

= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2001 GOTOU YUUZOU <gotoyuzo@notwork.org>
  All rights reserved.

= Licence
  This program is licenced under the same licence as Ruby.
  (See the file 'LICENCE'.)

= Version
  $Id$
=end

require "openssl/buffering"
require "fcntl"

module OpenSSL
  module SSL
    class SSLContext
      DEFAULT_PARAMS = {
        :ssl_version => "SSLv23",
        :verify_mode => OpenSSL::SSL::VERIFY_PEER,
        :ciphers => "ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW",
        :options => OpenSSL::SSL::OP_ALL,
      }

      DEFAULT_CERT_STORE = OpenSSL::X509::Store.new
      DEFAULT_CERT_STORE.set_default_paths
      if defined?(OpenSSL::X509::V_FLAG_CRL_CHECK_ALL)
        DEFAULT_CERT_STORE.flags = OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
      end

      def set_params(params={})
        params = DEFAULT_PARAMS.merge(params)
        # ssl_version need to be set at first.
        self.ssl_version = params.delete(:ssl_version)
        params.each{|name, value| self.__send__("#{name}=", value) }
        if self.verify_mode != OpenSSL::SSL::VERIFY_NONE
          unless self.ca_file or self.ca_path or self.cert_store
            self.cert_store = DEFAULT_CERT_STORE
          end
        end
        return params
      end
    end

    module SocketForwarder
      def addr
        to_io.addr
      end

      def peeraddr
        to_io.peeraddr
      end

      def setsockopt(level, optname, optval)
        to_io.setsockopt(level, optname, optval)
      end

      def getsockopt(level, optname)
        to_io.getsockopt(level, optname)
      end

      def fcntl(*args)
        to_io.fcntl(*args)
      end

      def closed?
        to_io.closed?
      end

      def do_not_reverse_lookup=(flag)
        to_io.do_not_reverse_lookup = flag
      end
    end

    module Nonblock
      def initialize(*args)
        flag = File::NONBLOCK
        flag |= @io.fcntl(Fcntl::F_GETFL) if defined?(Fcntl::F_GETFL)
        @io.fcntl(Fcntl::F_SETFL, flag)
        super
      end
    end

    def verify_certificate_identity(cert, hostname)
      should_verify_common_name = true
      cert.extensions.each{|ext|
        next if ext.oid != "subjectAltName"
        id, ostr = OpenSSL::ASN1.decode(ext.to_der).value
        sequence = OpenSSL::ASN1.decode(ostr.value)
        sequence.value.each{|san|
          case san.tag
          when 2 # dNSName in GeneralName (RFC5280)
            should_verify_common_name = false
            reg = Regexp.escape(san.value).gsub(/\\\*/, "[^.]+")
            return true if verify_hostname(hostname, san.value)
          when 7 # iPAddress in GeneralName (RFC5280)
            should_verify_common_name = false
            # follows GENERAL_NAME_print() in x509v3/v3_alt.c
            if san.value.size == 4
              return true if san.value.unpack('C*').join('.') == hostname
            elsif san.value.size == 16
              return true if san.value.unpack('n*').map { |e| sprintf("%X", e) }.join(':') == hostname
            end
          end
        }
      }
      if should_verify_common_name
        cert.subject.to_a.each{|oid, value|
          if oid == "CN"
            reg = Regexp.escape(value).gsub(/\\\*/, "[^.]+")
            return true if verify_hostname(hostname, value)
          end
        }
      end
      return false
    end
    module_function :verify_certificate_identity

    def verify_hostname(hostname, san) # :nodoc:
      # RFC 5280, IA5String is limited to the set of ASCII characters
      return false if san =~ /[\x80-\xff]/
      return false if hostname =~ /[\x80-\xff]/

      # See RFC 6125, section 6.4.1
      # Matching is case-insensitive.
      san_parts = san.downcase.split(".")

      # TODO: this behavior should probably be more strict
      return san == hostname if san_parts.size < 2

      # Matching is case-insensitive.
      host_parts = hostname.downcase.split(".")

      # RFC 6125, section 6.4.3, subitem 2.
      # If the wildcard character is the only character of the left-most
      # label in the presented identifier, the client SHOULD NOT compare
      # against anything but the left-most label of the reference
      # identifier (e.g., *.example.com would match foo.example.com but
      # not bar.foo.example.com or example.com).
      return false unless san_parts.size == host_parts.size

      # RFC 6125, section 6.4.3, subitem 1.
      # The client SHOULD NOT attempt to match a presented identifier in
      # which the wildcard character comprises a label other than the
      # left-most label (e.g., do not match bar.*.example.net).
      return false unless verify_wildcard(host_parts.shift, san_parts.shift)

      san_parts.join(".") == host_parts.join(".")
    end
    module_function :verify_hostname

    def verify_wildcard(domain_component, san_component) # :nodoc:
      parts = san_component.split("*", -1)

      return false if parts.size > 2
      return san_component == domain_component if parts.size == 1

      # RFC 6125, section 6.4.3, subitem 3.
      # The client SHOULD NOT attempt to match a presented identifier
      # where the wildcard character is embedded within an A-label or
      # U-label of an internationalized domain name.
      return false if domain_component.start_with?("xn--") && san_component != "*"

      parts[0].length + parts[1].length < domain_component.length &&
      domain_component.start_with?(parts[0]) &&
      domain_component.end_with?(parts[1])
    end
    module_function :verify_wildcard

    class SSLSocket
      include Buffering
      include SocketForwarder
      include Nonblock

      def post_connection_check(hostname)
        unless OpenSSL::SSL.verify_certificate_identity(peer_cert, hostname)
          raise SSLError, "hostname was not match with the server certificate"
        end
        return true
      end

      def session
        SSL::Session.new(self)
      rescue SSL::Session::SessionError
        nil
      end
    end

    class SSLServer
      include SocketForwarder
      attr_accessor :start_immediately

      def initialize(svr, ctx)
        @svr = svr
        @ctx = ctx
        unless ctx.session_id_context
          session_id = OpenSSL::Digest::MD5.hexdigest($0)
          @ctx.session_id_context = session_id
        end
        @start_immediately = true
      end

      def to_io
        @svr
      end

      def listen(backlog=5)
        @svr.listen(backlog)
      end

      def shutdown(how=Socket::SHUT_RDWR)
        @svr.shutdown(how)
      end

      def accept
        sock = @svr.accept
        begin
          ssl = OpenSSL::SSL::SSLSocket.new(sock, @ctx)
          ssl.sync_close = true
          ssl.accept if @start_immediately
          ssl
        rescue SSLError => ex
          sock.close
          raise ex
        end
      end

      def close
        @svr.close
      end
    end
  end
end
