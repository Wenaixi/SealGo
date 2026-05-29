class Sealgo < Formula
  desc "XChaCha20-Poly1305 multi-recipient encrypt/decrypt CLI"
  homepage "https://github.com/Wenaixi/SealGo"
  version "#__VERSION__"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Wenaixi/SealGo/releases/download/#{version}/SealGo-darwin-arm64"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000" # will be filled after first release
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Wenaixi/SealGo/releases/download/#{version}/SealGo-darwin-amd64"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  elsif OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
    url "https://github.com/Wenaixi/SealGo/releases/download/#{version}/SealGo-linux-arm64"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Wenaixi/SealGo/releases/download/#{version}/SealGo-linux-amd64"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  def install
    bin.install Dir["SealGo-*"].first => "SealGo"
  end

  test do
    output = shell_output("#{bin}/SealGo version")
    assert_match "SealGo #{version}", output
  end
end