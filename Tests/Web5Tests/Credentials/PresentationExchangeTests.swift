import XCTest

@testable import Web5

class PresentationExchangeTests: XCTestCase {
    
    func testSelectCredentialsWhenMatchesFound() throws {
        let vcJwt = """
        eyJraWQiOiJkaWQ6a2V5OnpRM3NoTkx0MWFNV1BiV1JHYThWb2VFYkpvZko3eEplNEZDUHBES3hxMU5aeWdwaXkjelEzc2hOTHQxYU1XUGJXUkdhOFZvZUViSm9mSjd4SmU0RkNQcERLeHExTlp5Z3BpeSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJpc3MiOiJkaWQ6a2V5OnpRM3NoTkx0MWFNV1BiV1JHYThWb2VFYkpvZko3eEplNEZDUHBES3hxMU5aeWdwaXkiLCJzdWIiOiJkaWQ6a2V5OnpRM3Noa3BhdmpLUmV3b0JrNmFyUEpuaEE4N1p6aExERVdnVnZaS05ISzZRcVZKREIiLCJpYXQiOjE3MDEzMDI1OTMsInZjIjp7Imlzc3VhbmNlRGF0ZSI6IjIwMjMtMTEtMzBUMDA6MDM6MTNaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6a2V5OnpRM3Noa3BhdmpLUmV3b0JrNmFyUEpuaEE4N1p6aExERVdnVnZaS05ISzZRcVZKREIiLCJsb2NhbFJlc3BlY3QiOiJoaWdoIiwibGVnaXQiOnRydWV9LCJpZCI6InVybjp1dWlkOjZjOGJiY2Y0LTg3YWYtNDQ5YS05YmZiLTMwYmYyOTk3NjIyNyIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJTdHJlZXRDcmVkIl0sIkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImlzc3VlciI6ImRpZDprZXk6elEzc2hOTHQxYU1XUGJXUkdhOFZvZUViSm9mSjd4SmU0RkNQcERLeHExTlp5Z3BpeSJ9fQ.qoqF4-FinFsQ2J-NFSO46xCE8kUTZqZCU5fYr6tS0TQ6VP8y-ZnyR6R3oAqLs_Yo_CqQi23yi38uDjLjksiD2w
        """
        
        let vcJwt2 = """
        eyJraWQiOiJkaWQ6andrOmV5SnJkSGtpT2lKRlF5SXNJblZ6WlNJNkluTnBaeUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW10cFpDSTZJazVDWDNGc1ZVbHlNRFl0UVdsclZsWk5SbkpsY1RCc1l5MXZiVkYwZW1NMmJIZG9hR04yWjA4MmNqUWlMQ0o0SWpvaVJHUjBUamhYTm5oZk16UndRbDl1YTNoU01HVXhkRzFFYTA1dWMwcGxkWE5DUVVWUWVrdFhaMlpmV1NJc0lua2lPaUoxTTFjeE16VnBibTlrVEhGMFkwVmlPV3BPUjFNelNuTk5YM1ZHUzIxclNsTmlPRlJ5WXpsc2RWZEpJaXdpWVd4bklqb2lSVk15TlRaTEluMCMwIiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTZLIn0.eyJpc3MiOiJkaWQ6andrOmV5SnJkSGtpT2lKRlF5SXNJblZ6WlNJNkluTnBaeUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW10cFpDSTZJazVDWDNGc1ZVbHlNRFl0UVdsclZsWk5SbkpsY1RCc1l5MXZiVkYwZW1NMmJIZG9hR04yWjA4MmNqUWlMQ0o0SWpvaVJHUjBUamhYTm5oZk16UndRbDl1YTNoU01HVXhkRzFFYTA1dWMwcGxkWE5DUVVWUWVrdFhaMlpmV1NJc0lua2lPaUoxTTFjeE16VnBibTlrVEhGMFkwVmlPV3BPUjFNelNuTk5YM1ZHUzIxclNsTmlPRlJ5WXpsc2RWZEpJaXdpWVd4bklqb2lSVk15TlRaTEluMCIsInN1YiI6ImRpZDprZXk6elEzc2hrcGF2aktSZXdvQms2YXJQSm5oQTg3WnpoTERFV2dWdlpLTkhLNlFxVkpEQiIsImlhdCI6MTcwMTMwMjU5MywidmMiOnsiaXNzdWFuY2VEYXRlIjoiMjAyMy0xMS0zMFQwMDowMzoxM1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6elEzc2hrcGF2aktSZXdvQms2YXJQSm5oQTg3WnpoTERFV2dWdlpLTkhLNlFxVkpEQiIsImxvY2FsUmVzcGVjdCI6ImhpZ2giLCJsZWdpdCI6dHJ1ZX0sImlkIjoidXJuOnV1aWQ6NmM4YmJjZjQtODdhZi00NDlhLTliZmItMzBiZjI5OTc2MjI3IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlN0cmVldENyZWQiXSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaXNzdWVyIjoiZGlkOmp3azpleUpyZEhraU9pSkZReUlzSW5WelpTSTZJbk5wWnlJc0ltTnlkaUk2SW5ObFkzQXlOVFpyTVNJc0ltdHBaQ0k2SWs1Q1gzRnNWVWx5TURZdFFXbHJWbFpOUm5KbGNUQnNZeTF2YlZGMGVtTTJiSGRvYUdOMlowODJjalFpTENKNElqb2lSR1IwVGpoWE5uaGZNelJ3UWw5dWEzaFNNR1V4ZEcxRWEwNXVjMHBsZFhOQ1FVVlFla3RYWjJaZldTSXNJbmtpT2lKMU0xY3hNelZwYm05a1RIRjBZMFZpT1dwT1IxTXpTbk5OWDNWR1MyMXJTbE5pT0ZSeVl6bHNkVmRKSWl3aVlXeG5Jam9pUlZNeU5UWkxJbjAifX0.8AehkiboIK6SZy6LHC9ugy_OcT2VsjluzH4qzsgjfTtq9fEsGyY-cOW_xekNUa2RE2VzlP6FXk0gDn4xf6_r4g
        """
        
        let pd = PresentationDefinitionV2(
            inputDescriptors: [
                InputDescriptorV2(
                    constraints: ConstraintsV2(
                        fields: [
                            FieldV2(
                                path: ["$.credentialSubject.legit"],
                                filter: ["type":"boolean"]
                            ),
                            FieldV2(
                                path: ["$.credentialSubject.localRespect"],
                                filter: ["type":"string", "const": "high"]
                            ),
                            FieldV2(
                                path: ["$.issuer"],
                                optional: false
                            )
                        ]
                    )
                )
            ]
        )
        
        let result = try PresentationExchange.selectCredentials(vcJWTs: [vcJwt, vcJwt2], presentationDefinition: pd)
        
        XCTAssertEqual(result, [vcJwt, vcJwt2])
    }
}
