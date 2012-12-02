#!/usr/bin/perl
# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://sam.zoy.org/wtfpl/COPYING for more details.

use warnings;
use strict;

use MIME::Base32 qw(RFC);
use Digest::SHA qw(sha256 hmac_sha256);
use Crypt::CBC;
use Time::HiRes qw(usleep);
#use Term::ProgressBar;
use Data::Dumper;
use Net::DNS;

my $DEBUG   = $ENV{DEBUG} || 0; 

my $NAMESRV = $ARGV[0];
my $DOMAIN  = $ARGV[1];
my $KEY     = $ARGV[2];
my $DATA    = $ARGV[3];

# Encryption inflates the data size, but is 'secure'
my $ENCRYPT = 1;

# Try to make this happen a little faster, may need to be tweaked.
my $res = Net::DNS::Resolver->new(
            nameservers => [$NAMESRV],
            persistent_udp => 1,
            retrans => 1,
            retry => 5,
          );

upload($NAMESRV, $DOMAIN, $KEY, $DATA) if ($DATA);
print "Upload complete!\n" if ($DATA);
my $dl_data = download($NAMESRV, $DOMAIN, $KEY);

if ($DATA) {
  if ($dl_data eq $DATA) {
    print "Verification successful! :-)\n";
  } else {
    print "Verification failed! :'(\n";
  }
} else {
  print "$dl_data\n";
}

# Upload a chunk of data to a dns cache
# TODO: DoS^W asyncronous mode 
sub upload {
  my $nameserver = shift;
  my $domain     = shift;
  my $key        = shift;
  my $data       = shift;

  my $ctr = 0;

  my $encr_k = gen_key("encr;$domain", $key);
  my $hash_k = gen_key("hash;$domain", $key);
  my $hmac_k = gen_key("hmac;$domain", $key);

  # Using Blowfish instead of AES/Rijndael because it uses a smaller block
  # size, resulting in a bit less data inflation
  my $cipher = Crypt::CBC->new(
    -cipher      => 'Blowfish',
    -literal_key => 1,
    -keysize     => 32, # 256 bits
    -header      => 'none',
    -iv          => "\x01\x23\x45\x67\x89\xab\xcd\xef",
    -key         => $encr_k,
  );

  my $enc = $ENCRYPT ? $cipher->encrypt($data) : $data;

  my $enc_h = base32_encode(hmac_sha256($enc, $hmac_k));

  while ($enc =~ s/\A(.{1,38})(.*)\z/$2/s) {
    #my $d1 = base32_encode($1);
    my $d2 = base32_encode(substr(sha256($ctr . $hash_k), 0, 10));
    my @bits = split(//, unpack('B*', $1));

    my $i = 0;
    my $buf = '';
    my $chr_v = 0;

    # Generate probeable records from left to right - big endian
    while (defined(my $bit = shift @bits)) {
      my $b_pos = $i % 8; # bit position
      $chr_v |= $bit << (7 - $b_pos);
      dns_poke("$b_pos." . base32_encode($buf . chr($chr_v)) . ".$d2.$domain");
      if ($b_pos == 7) {
        $buf .= chr($chr_v);
        $chr_v = 0;
      }
      $i++;
    }
    #print STDERR "FINAL: 7.$d1.$d2.$domain\n";

    $ctr++;
  }
  my $d2 = base32_encode(substr(sha256($ctr . $hash_k), 0, 10));
  print STDERR "CKSUM: $enc_h.$d2.$domain\n";
  dns_poke("$enc_h.$d2.$domain");

  return 1;
}

# Download a chunk of data that's been stored in a dns cache with the upload function
# TODO: DoS^W asyncronous mode 
sub download {
  my $nameserver = shift;
  my $domain     = shift;
  my $key        = shift;

  my $ctr = 0;

  my $encr_k = gen_key("encr;$domain", $key);
  my $hash_k = gen_key("hash;$domain", $key);
  my $hmac_k = gen_key("hmac;$domain", $key);

  # Using Blowfish instead of AES/Rijndael because it uses a smaller block
  # size, resulting in a bit less data inflation
  my $cipher = Crypt::CBC->new(
    -cipher      => 'Blowfish',
    -literal_key => 1,
    -keysize     => 32, # 256 bits
    -header      => 'none',
    -iv          => "\x01\x23\x45\x67\x89\xab\xcd\xef",
    -key         => $encr_k,
  );
  
  my $data = '';

  while (1) {
    my $d2 = base32_encode(substr(sha256($ctr . $hash_k), 0, 10));
    my $base = ".$d2.$domain";
    my @bits = ();

    my $i = 0;
    my $chr_v = 0;
    my $buf = '';

    # Probe for bit values from left to right - big endian
    while (1) {
      my $b_pos = $i % 8; # bit position
      if (dns_peek("$b_pos." . base32_encode($buf . chr($chr_v)) . $base)) { # a 0 bit
        push(@bits, 0); 
      } elsif (dns_peek("$b_pos." . base32_encode($buf . chr($chr_v | (1 << (7 - $b_pos)))) . $base)) { # a 1 bit
        $chr_v |= 1 << (7 - $b_pos);
        push(@bits, 1); 
      } else { # all out of putty tats^W^Wbits
        die "Missing record!" unless ($b_pos == 0);
        if ($i == 0) {
          # Check for a correct data checksum
          my $enc_h = base32_encode(hmac_sha256($data, $hmac_k));
          $d2 = base32_encode(substr(sha256($ctr . $hash_k), 0, 10));
          if (dns_peek("$enc_h.$d2.$domain")) {
            #print STDERR "Download successful!\n";
            return $ENCRYPT ? $cipher->decrypt($data) : $data;
            #last OUTER;
          } else {
            die "Matching hash not found!";
          }
        } else {
          #last INNER;
          last;
        }
      }
      if ($b_pos == 7) {
        $buf .= chr($chr_v);
        $chr_v = 0;
      }
      $i++;
    }
    $data .= $buf;
    $ctr++;
  }

  # How did we get here? We should have returned from within the loop or die'd.
  return undef;
}

sub dns_poke {
  my $fqdn = shift;

  $res->recurse(1);
  print STDERR "FQDN:  $fqdn\n" if ($DEBUG);
  my $ans = $res->query($fqdn);
  die "dns_poke '$fqdn' failed" unless ($ans->header->rcode eq 'NOERROR'); # this will bomb on an NXDOMAIN - on purpose.
  return 1;
}

sub dns_peek {
  my $fqdn = shift;

  $res->recurse(0); # Heisenberg compensator - ask the cache but don't chage it
  print STDERR "FQDN:  $fqdn\n" if ($DEBUG);
  my $ans = $res->send($fqdn); # query will do processing that will fuck this up
  die "dns_peek '$fqdn' failed" unless ($ans->header->rcode eq 'NOERROR');
  return $ans->header->ancount;
}

sub gen_key {
  my $salt = shift;
  my $pass = shift;
  my $iter = shift || 100_000;

  # PBKDF2 with dklen == hlen
  my $t = hmac_sha256($salt . pack('N', 1), $pass);
  my $u = $t;
  for (my $i = 2; $i <= $iter; $i++) {
    $t ^= $u = hmac_sha256($u, $pass);
  }
  return $t;
}

# Some shortcuts
sub base32_encode  { return lc(MIME::Base32::encode(shift)); }
sub base32_decode  { return lc(MIME::Base32::decode(shift)); }
sub scalar_reverse { return scalar reverse shift; }
# vim: ts=2 sw=2 et ai si
