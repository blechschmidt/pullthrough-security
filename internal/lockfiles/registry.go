package lockfiles

// builtinParsers returns every built-in parser, in detection order. Each
// format's file names are distinct, so the order only matters for a path two
// parsers could both claim — there is none (TestDetectIsUnambiguous).
func builtinParsers() []Parser {
	return []Parser{
		// npm
		npmLock{file: "package-lock.json"},
		npmLock{file: "npm-shrinkwrap.json"},
		yarnLock{},
		pnpmLock{},
		// pip
		requirementsTxt{},
		pipfileLock{},
		poetryLock{},
		uvLock{},
		pdmLock{},
		// cargo
		cargoLock{},
		// go
		goMod{},
		goSum{},
		// nuget
		nugetLock{},
		// maven
		gradleLock{},
		pomXML{},
		// rubygems
		gemfileLock{},
		// composer
		composerLock{},
		// docker
		dockerfile{},
		composeFile{},
	}
}
