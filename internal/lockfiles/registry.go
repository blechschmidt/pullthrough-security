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
		// conda
		condaLock{},
		condaExplicit{},
		pixiLock{},
		// cran
		renvLock{},
		// hex
		mixLock{},
		// swift
		packageResolved{},
		// dart
		pubspecLock{},
		// julia
		juliaManifest{},
		// bazel
		moduleBazelLock{},
		// nix
		flakeLock{},
		// terraform
		terraformLock{},
		terraformModules{},
		terraformOverrides{},
		// conan
		conanLock{},
		// cpan
		cpanfileSnapshot{},
		// hackage
		cabalFreeze{},
		stackLock{},
		// jsr
		denoLock{},
		// helm
		chartLock{},
		requirementsLock{},
		// homebrew
		brewfileLock{},
		// ansible
		ansibleRequirements{},
		// puppet
		puppetfile{},
		// git
		gitmodules{},
	}
}
