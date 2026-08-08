import CSodium

/// A namespace for safe, high-level libsodium operations.
public enum Sodium: Sendable {
  private static let initialization: Result<Void, SodiumError> = {
    if sodium_init() >= 0 {
      .success(())
    } else {
      .failure(.initializationFailed)
    }
  }()

  /// Initializes libsodium.
  ///
  /// Initialization is thread-safe and performed at most once. Public operations call this
  /// automatically, so applications normally do not need to invoke it directly.
  public static func initialize() throws {
    try initialization.get()
  }

  /// The linked libsodium version.
  public static var version: String {
    guard let version = sodium_version_string() else { return "unknown" }
    return String(cString: version)
  }
}
