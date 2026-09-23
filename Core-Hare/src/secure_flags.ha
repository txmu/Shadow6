use fs;

fn secure_open_flags() fs::flag =
	fs::flag::RDONLY | fs::flag::NOFOLLOW | fs::flag::NONBLOCK;
