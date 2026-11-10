// Minimal real NuGet build for the pull-through proxy test set.
using Newtonsoft.Json;

var json = JsonConvert.SerializeObject(new { ok = true });
System.Console.WriteLine(json);
