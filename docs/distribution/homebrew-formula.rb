class Secureship < Formula
  desc "Zero-telemetry local-first security CLI for supply chain, SAST, secrets, and SCA"
  homepage "https://secureship.dev"
  version "1.0.0-beta.1"

  on_macos do
    on_arm do
      url "https://github.com/secureship/secureship/releases/download/v#{version}/secureship-darwin-arm64"
      sha256 "REPLACE_AFTER_RELEASE"
    end
    on_intel do
      url "https://github.com/secureship/secureship/releases/download/v#{version}/secureship-darwin-x64"
      sha256 "REPLACE_AFTER_RELEASE"
    end
  end

  def install
    binary = Hardware::CPU.arm? ? "secureship-darwin-arm64" : "secureship-darwin-x64"
    bin.install binary => "secureship"
  end

  test do
    assert_match "SecureShip", shell_output("#{bin}/secureship --version")
  end
end
