// Minimal Deno program that depends on one real JSR package (@luca/flag).
// Resolved through the proxy when JSR_URL points at <proxy>/v1/jsr.
import { printProgress } from "@luca/flag";

printProgress();
