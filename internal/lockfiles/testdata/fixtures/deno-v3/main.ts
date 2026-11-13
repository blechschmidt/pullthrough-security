import { assertEquals } from "@std/assert";
import { join } from "@std/path";
import ansiRegex from "ansi-regex";
import chalk from "chalk";
import { version } from "esbuild";
import leftPad from "left-pad";
import stripAnsi from "strip-ansi";
import { green } from "colors";
import { bold } from "https://deno.land/std/fmt/colors.ts";

assertEquals(join("a", "b"), "a/b");
console.log(ansiRegex().test(chalk.blue("x")), stripAnsi(green(bold(leftPad(version, 8)))));
