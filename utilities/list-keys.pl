use strict;

my %keys = ();
my $currentKeyId = undef;

while (<STDIN>) {
	chomp($_);
	my @fields = split(':', $_);

	if ($_ =~ m/^(pub|sec):/) {
		$currentKeyId = $fields[4];
		$keys{$currentKeyId} = {uid => $fields[9], type => $1, sub => []};
		next;
	}

	if ($_ =~ m/^fpr:/) {
		$keys{$currentKeyId}->{fpr} = $fields[9];
		next;
	}

	if ($_ =~ m/^(sub|ssb):/) {
		push(@{$keys{$currentKeyId}->{sub}}, $fields[4]);
		next;
	}
}

my @lines = ();
foreach my $key (keys %keys) {
	my @fields = ($keys{$key}->{type}, $key, $keys{$key}->{fpr});

	foreach my $subid (@{$keys{$key}->{sub}}) {
		push(@fields, $subid);
	}
	push(@fields, $keys{$key}->{uid});
	unshift(@fields, sprintf("%-3s", int(@fields)+1));
	push(@lines, join(' ', @fields));
}

print join("\n", @lines) . "\n";

