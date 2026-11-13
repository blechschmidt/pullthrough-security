# Evaluates versions and ranges with NuGet.Versioning: allowed is
# VersionRange.IsBetter(null, v) (the bounds and the pre-release rule) and, for
# a floating range, FloatRange.Satisfies(v).
# Usage: pwsh -File nuget.ps1 -VersionsFile v.lines -ConstraintsFile c.lines -OutDir dir -Dll NuGet.Versioning.dll
param([string]$VersionsFile, [string]$ConstraintsFile, [string]$OutDir, [int]$UniverseSize = 200, [string]$Dll)
$script:UniverseSize = $UniverseSize
Add-Type -Path $Dll
function Q([string]$s) { return (ConvertTo-Json -Compress -InputObject $s) }
$vers = [System.Collections.Generic.List[string]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new()
foreach ($line in [System.IO.File]::ReadAllLines($VersionsFile)) { if ($line -eq '') { continue }; $s = [System.Text.Json.JsonSerializer]::Deserialize[string]($line); if ($seen.Add($s)) { $vers.Add($s) } }
$cons = [System.Collections.Generic.List[string]]::new()
$seen2 = [System.Collections.Generic.HashSet[string]]::new()
foreach ($line in [System.IO.File]::ReadAllLines($ConstraintsFile)) { if ($line -eq '') { continue }; $s = [System.Text.Json.JsonSerializer]::Deserialize[string]($line); if ($seen2.Add($s)) { $cons.Add($s) } }
# Static TryParse overloads of NuGetVersion and its base SemanticVersion
# differ only in the out type; call the intended ones by reflection.
$script:tryVersion = [NuGet.Versioning.NuGetVersion].GetMethod('TryParse', [type[]]@([string], [NuGet.Versioning.NuGetVersion].MakeByRefType()))
$script:tryRange = [NuGet.Versioning.VersionRange].GetMethod('TryParse', [type[]]@([string], [bool], [NuGet.Versioning.VersionRange].MakeByRefType()))
$parsed = @{}
$valid = [System.Collections.Generic.List[NuGet.Versioning.NuGetVersion]]::new()
foreach ($v in $vers) {
  $a = [object[]]@([string]$v, $null)
  if ($script:tryVersion.Invoke($null, $a)) { $parsed[$v] = $a[1]; $valid.Add($a[1]) }
}
$cmp = [NuGet.Versioning.VersionComparer]::Default
$valid.Sort([System.Collections.Generic.IComparer[NuGet.Versioning.NuGetVersion]]$cmp)
$sb = [System.Text.StringBuilder]::new()
foreach ($v in $vers) {
  $rank = -1
  if ($parsed.ContainsKey($v)) {
    $r = -1; $prev = $null
    foreach ($x in $valid) { if ($null -eq $prev -or $cmp.Compare($prev, $x) -ne 0) { $r++ }; if ($cmp.Compare($x, $parsed[$v]) -eq 0) { break }; $prev = $x }
    $rank = $r
  }
  [void]$sb.Append((Q $v) + "`t" + $rank + "`n")
}
[System.IO.File]::WriteAllText("$OutDir/nuget-versions.tsv", $sb.ToString())
$universe = @($vers | Where-Object { $parsed.ContainsKey($_) } | Select-Object -First $script:UniverseSize)
$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append('# [' + (($universe | ForEach-Object { Q $_ }) -join ',') + "]`n")
foreach ($c in $cons) {
  $range = $null
  $ok = $false
  $a = [object[]]@([string]$c, $true, $null)
  try { $ok = $script:tryRange.Invoke($null, $a); $range = $a[2] } catch { $ok = $false }
  if (-not $ok) { [void]$sb.Append((Q $c) + "`tinvalid`t`t`n"); continue }
  $bits = ''
  foreach ($u in $universe) {
    $v = $parsed[$u]
    $allowed = $range.IsBetter($null, $v)
    if ($allowed -and $range.IsFloating) { $allowed = $range.Float.Satisfies($v) }
    $bits += $(if ($allowed) { '1' } else { '0' })
  }
  [void]$sb.Append((Q $c) + "`tok`t`t" + $bits + "`n")
}
[System.IO.File]::WriteAllText("$OutDir/nuget-constraints.tsv", $sb.ToString())
Write-Output "$($vers.Count) versions, $($valid.Count) valid, $($cons.Count) ranges"
