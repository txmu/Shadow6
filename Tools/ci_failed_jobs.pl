#!/usr/bin/env perl
use strict;
use warnings;
use JSON::PP qw(decode_json);

die "usage: ci_failed_jobs.pl RUN_JSON\n" unless @ARGV == 1;
open my $input, '<', $ARGV[0] or die "$ARGV[0]: $!\n";
local $/;
my $run = decode_json(<$input>);
die "expected run with jobs array\n" unless ref($run) eq 'HASH' && ref($run->{jobs}) eq 'ARRAY';
my @failed = sort map { $_->{name} }
    grep { ref($_) eq 'HASH' && ($_->{conclusion} // '') eq 'failure' && defined $_->{name} }
    @{$run->{jobs}};
print "$_\n" for @failed;
printf "failed jobs: %d\n", scalar @failed;
