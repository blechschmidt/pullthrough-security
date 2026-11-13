# Evaluates versions and requirements with RubyGems: Gem::Version,
# Gem::Requirement (a requirement string is split at commas, as Gemfile.lock
# writes several), and Gem::Dependency#match?'s pre-release rule.
# Usage: ruby rubygems.rb versions.lines constraints.lines outdir
require 'json'
vfile, cfile, outdir = ARGV
vers = File.readlines(vfile, chomp: true).reject(&:empty?).map { |l| JSON.parse("[#{l}]")[0] }.uniq
cons = File.readlines(cfile, chomp: true).reject(&:empty?).map { |l| JSON.parse("[#{l}]")[0] }.uniq
parsed = {}
vers.each { |v| begin; parsed[v] = Gem::Version.new(v) if Gem::Version.correct?(v) && !v.nil?; rescue ArgumentError; end }
valid = parsed.values.sort
File.open("#{outdir}/rubygems-versions.tsv", 'w') do |f|
  vers.each do |v|
    p = parsed[v]
    rr = -1
    if p
      rr = 0; pr = nil
      valid.each { |x| rr += 1 if !pr.nil? && (pr <=> x) != 0; break if (x <=> p) == 0; pr = x }
    end
    f.puts "#{JSON.generate(v)}\t#{rr}"
  end
end
universe = vers.select { |v| parsed[v] }.first((ENV["UNIVERSE"] || "220").to_i)
File.open("#{outdir}/rubygems-constraints.tsv", 'w') do |f|
  f.puts "# #{JSON.generate(universe)}"
  cons.each do |c|
    parts = c.split(',', -1)
    req = begin
      Gem::Requirement.new(*parts)
    rescue Gem::Requirement::BadRequirementError, ArgumentError
      nil
    end
    if req.nil?
      f.puts "#{JSON.generate(c)}\tinvalid\t\t"
      next
    end
    dep = Gem::Dependency.new('x', req)
    bits = universe.map { |v| dep.match?('x', parsed[v]) ? '1' : '0' }.join
    f.puts "#{JSON.generate(c)}\tok\t\t#{bits}"
  end
end
puts "#{Gem::VERSION}: #{vers.size} versions, #{valid.size} valid, #{cons.size} requirements"
