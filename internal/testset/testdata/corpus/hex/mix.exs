defmodule PullthroughTestset.MixProject do
  use Mix.Project

  # Minimal real Mix project for the pull-through test set. It declares one tiny,
  # ubiquitous, real Hex dependency (jason, a JSON library). Point mix/hex at the
  # proxy and resolve it through the mount:
  #
  #   HEX_MIRROR=https://proxy.example.com/v1/hex mix deps.get
  #
  # mix fetches the signed /packages/jason registry resource and then the
  # immutable /tarballs/jason-1.4.1.tar release tarball, both through the proxy.
  def project do
    [
      app: :pullthrough_testset,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:jason, "1.4.1"}
    ]
  end
end
