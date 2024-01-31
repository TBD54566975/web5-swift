import XCTest

/// Representation of a test vector
///
/// This representation uses the following generics:
///   - Input: Type of the file's vector object `input` property. This is unique for each test vector file, and should
///   be defined in the vector's README file.
///   - Output: Type of the file's vector object `output` property. This is unique for each test vector file, and should
///   be defined in the vector's README file.
///
/// [Specification Reference](https://github.com/TBD54566975/sdk-development/tree/main/web5-test-vectors)
struct TestVector<Input: Codable, Output: Codable>: Codable {

    /// A general description of the test vectors collection.
    private let description: String

    /// An array of test vector objects.
    private let vectors: [Vector]

    /// Default Initializer
    /// - Parameters:
    ///   - fileName: Name of the JSON file containing the test vectors.
    ///   - subdirectory: Name of subdirectory that contains `fileName`. Used to disambiguate when there are multiple
    ///   test vector files with the same name.
    init(
        fileName: String,
        subdirectory: String? = nil
    ) throws {
        guard
            let url = Bundle.module.url(
                forResource: fileName,
                withExtension: "json",
                subdirectory: subdirectory
            )
        else {
            fatalError("Missing file: \(fileName).json")
        }

        let data = try Data(contentsOf: url)
        self = try JSONDecoder().decode(Self<Input, Output>.self, from: data)
    }

    /// Run a test vector, individually executing each vector object defined within it.
    ///
    /// - Parameters:
    ///   - vectorHandler: Closure that will be executed with each vector object defined within the test vector file.
    ///   This is where you write your assertions!
    func run(
        vectorHandler: (Vector) throws -> Void
    ) {
        XCTContext.runActivity(named: description) { _ in
            for vector in vectors {
                do {
                    try XCTContext.runActivity(named: vector.description) { _ in
                        try vectorHandler(vector)
                    }
                } catch {
                    XCTFail("Unexpected error: \(error)")
                }
            }
        }
    }
}

extension TestVector {

    /// Representation of individual vector object that appears within a test vector file
    ///
    /// [Specification Reference](https://github.com/TBD54566975/sdk-development/tree/main/web5-test-vectors)
    struct Vector: Codable {

        /// A description of what this test vector is testing.
        let description: String

        /// The input for the test vector, which can be of any type.
        let input: Input

        /// The expected output for the test vector, which can be of any type.
        let output: Output?

        /// Indicates whether the test vector is expected to produce an error.
        let errors: Bool?
    }
}
