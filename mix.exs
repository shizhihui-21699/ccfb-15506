defmodule SafeFinder.MixProject do
  use Mix.Project

  def project do
    [
      app: :safefinder,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      test_coverage: [summary: [threshold: 80]]
    ]
  end

  def application do
    [
      mod: application_mod(Mix.env()),
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  # Tests start isolated, anonymous processes themselves; autostarting the
  # named supervision tree would collide with them.
  defp application_mod(:test), do: []
  defp application_mod(_), do: {SafeFinder.Application, []}

  defp deps, do: []

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
