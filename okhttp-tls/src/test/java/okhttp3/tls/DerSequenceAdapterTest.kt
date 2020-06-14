/*
 * Copyright (C) 2020 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package okhttp3.tls

import okhttp3.tls.internal.der.AnyValue
import okhttp3.tls.internal.der.DerAdapter
import okhttp3.tls.internal.der.DerReader
import okhttp3.tls.internal.der.DerSequenceAdapter
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test
import java.math.BigInteger
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

internal class DerSequenceAdapterTest {
  @Test fun `decode point with only x set`() {
    val buffer = Buffer()
        .write("3003800109".decodeHex())
    val derReader = DerReader(buffer)
    val point = Point.ADAPTER.readWithTagAndLength(derReader)
    assertThat(point).isEqualTo(Point(9L, null))
  }

  @Test fun `decode point with only y set`() {
    val buffer = Buffer()
        .write("3003810109".decodeHex())
    val derReader = DerReader(buffer)
    val point = Point.ADAPTER.readWithTagAndLength(derReader)
    assertThat(point).isEqualTo(Point(null, 9L))
  }

  @Test fun `decode point with both fields set`() {
    val buffer = Buffer()
        .write("3006800109810109".decodeHex())
    val derReader = DerReader(buffer)
    val point = Point.ADAPTER.readWithTagAndLength(derReader)
    assertThat(point).isEqualTo(Point(9L, 9L))
  }

  @Test fun `decode implicit`() {
    // [5] IMPLICIT UTF8String
    val implicitAdapter = DerAdapter.UTF8_STRING.copy(
        tagClass = DerReader.TAG_CLASS_CONTEXT_SPECIFIC,
        tag = 5
    )

    val buffer = Buffer().write("85026869".decodeHex())
    val derReader = DerReader(buffer)
    val string = implicitAdapter.readWithTagAndLength(derReader)
    assertThat(string).isEqualTo("hi")
  }

  @Test fun `decode explicit`() {
    // [5] EXPLICIT UTF8String
    val explicitAdapter = DerAdapter.UTF8_STRING.withExplicitBox(
        tagClass = DerReader.TAG_CLASS_CONTEXT_SPECIFIC,
        tag = 5
    )

    val buffer = Buffer().write("A5040C026869".decodeHex())
    val derReader = DerReader(buffer)
    val string = explicitAdapter.readWithTagAndLength(derReader)
    assertThat(string).isEqualTo("hi")
  }

  @Test fun `decode positive integer`() {
    val adapter = DerAdapter.INTEGER_AS_LONG
    val buffer = Buffer()
        .writeByte(adapter.tagClass or adapter.tag.toInt())
        .writeByte(1)
        .writeByte(0b00110010)
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader)).isEqualTo(50L)
  }

  @Test fun `decode negative integer`() {
    val adapter = DerAdapter.INTEGER_AS_LONG
    val buffer = Buffer()
        .writeByte(adapter.tagClass or adapter.tag.toInt())
        .writeByte(1)
        .writeByte(0b10011100)
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader)).isEqualTo(-100L)
  }

  @Test fun `decode five byte integer`() {
    val adapter = DerAdapter.INTEGER_AS_LONG
    val buffer = Buffer()
        .writeByte(adapter.tagClass or adapter.tag.toInt())
        .writeByte(5)
        .writeByte(0b10000000)
        .writeByte(0b00000000)
        .writeByte(0b00000000)
        .writeByte(0b00000000)
        .writeByte(0b00000001)
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader)).isEqualTo(-549755813887L)
  }

  @Test fun `decode with eight zeros`() {
    val adapter = DerAdapter.INTEGER_AS_LONG
    val buffer = Buffer()
        .writeByte(adapter.tagClass or adapter.tag.toInt())
        .writeByte(2)
        .writeByte(0b00000000)
        .writeByte(0b11111111)
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader)).isEqualTo(255)
  }

  @Test fun `decode bigger than max long`() {
    val adapter = DerAdapter.INTEGER_AS_BIG_INTEGER
    val buffer = Buffer()
        .write("0209008000000000000001".decodeHex())
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader)).isEqualTo(BigInteger("9223372036854775809"))
  }

  @Test fun `decode utf8 string`() {
    val adapter = DerAdapter.UTF8_STRING
    val buffer = Buffer()
        .write("0c04f09f988e".decodeHex())
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader)).isEqualTo("\uD83D\uDE0E")
  }

  @Test fun `decode ia5`() {
    val adapter = DerAdapter.IA5_STRING
    val buffer = Buffer()
        .write("16026869".decodeHex())
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader)).isEqualTo("hi")
  }

  @Test fun `decode printable string`() {
    val adapter = DerAdapter.PRINTABLE_STRING
    val buffer = Buffer()
        .write("13026869".decodeHex())
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader)).isEqualTo("hi")
  }

  @Test fun `decode utc time`() {
    val adapter = DerAdapter.UTC_TIME
    val buffer = Buffer()
        .write("17113139313231353139303231302d30383030".decodeHex())
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader))
        .isEqualTo(date("2019-12-16T03:02:10.000+0000").time)
  }

  @Test fun `decode generalized time`() {
    val adapter = DerAdapter.GENERALIZED_TIME
    val buffer = Buffer()
        .write("171332303139313231353139303231302d30383030".decodeHex())
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader))
        .isEqualTo(date("2019-12-16T03:02:10.000+0000").time)
  }

  @Test fun `utc time two digit year cutoff is 1950`() {
    assertThat(DerAdapter.parseUtcTime("500101000000-0000"))
        .isEqualTo(date("1950-01-01T00:00:00.000+0000").time)
    assertThat(DerAdapter.parseUtcTime("500101000000-0100"))
        .isEqualTo(date("1950-01-01T01:00:00.000+0000").time)

    assertThat(DerAdapter.parseUtcTime("491231235959+0100"))
        .isEqualTo(date("2049-12-31T22:59:59.000+0000").time)
    assertThat(DerAdapter.parseUtcTime("491231235959-0000"))
        .isEqualTo(date("2049-12-31T23:59:59.000+0000").time)

    // Note that time zone offsets aren't honored by Java's two-digit offset boundary! A savvy time
    // traveler could exploit this to get a certificate that expires 100 years later than expected.
    assertThat(DerAdapter.parseUtcTime("500101000000+0100"))
        .isEqualTo(date("2049-12-31T23:00:00.000+0000").time)
    assertThat(DerAdapter.parseUtcTime("491231235959-0100"))
        .isEqualTo(date("2050-01-01T00:59:59.000+0000").time)
  }

  @Test fun `generalized time`() {
    assertThat(DerAdapter.parseGeneralizedTime("18990101000000-0000"))
        .isEqualTo(date("1899-01-01T00:00:00.000+0000").time)
    assertThat(DerAdapter.parseGeneralizedTime("19500101000000-0000"))
        .isEqualTo(date("1950-01-01T00:00:00.000+0000").time)
    assertThat(DerAdapter.parseGeneralizedTime("20500101000000-0000"))
        .isEqualTo(date("2050-01-01T00:00:00.000+0000").time)
    assertThat(DerAdapter.parseGeneralizedTime("20990101000000-0000"))
        .isEqualTo(date("2099-01-01T00:00:00.000+0000").time)
  }

  @Test fun `decode object identifier`() {
    val adapter = DerAdapter.OBJECT_IDENTIFIER
    val buffer = Buffer()
        .write("06092a864886f70d01010b".decodeHex())
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader))
        .isEqualTo("1.2.840.113549.1.1.11")
  }

  @Test fun `decode null`() {
    val adapter = DerAdapter.NULL
    val buffer = Buffer()
        .write("0500".decodeHex())
    val derReader = DerReader(buffer)
    assertThat(adapter.readWithTagAndLength(derReader)).isNull()
  }

  @Test fun `decode sequence algorithm`() {
    val adapter = AlgorithmIdentifier.ADAPTER
    val buffer = Buffer()
        .write("300d06092a864886f70d01010b0500".decodeHex())
    val derReader = DerReader(buffer)
    // TODO(jwilson): fix the tag and tagClass in the expected value.
    assertThat(adapter.readWithTagAndLength(derReader)).isEqualTo(
        AlgorithmIdentifier(
            algorithm = "1.2.840.113549.1.1.11",
            parameters = AnyValue(
                0, 0L, false, 0L, ByteString.EMPTY
            )
        )
    )
  }

  /**
   * ```
   * Point ::= SEQUENCE {
   *   x [0] INTEGER OPTIONAL,
   *   y [1] INTEGER OPTIONAL
   * }
   * ```
   */
  data class Point(
    val x: Long?,
    val y: Long?
  ) {
    companion object {
      val ADAPTER = DerSequenceAdapter(
          members = listOf(
              DerAdapter.INTEGER_AS_LONG.copy(
                  tagClass = DerReader.TAG_CLASS_CONTEXT_SPECIFIC,
                  tag = 0,
                  isOptional = true
              ),
              DerAdapter.INTEGER_AS_LONG.copy(
                  tagClass = DerReader.TAG_CLASS_CONTEXT_SPECIFIC,
                  tag = 1,
                  isOptional = true
              )
          )
      ) {
        Point(it[0] as Long?, it[1] as Long?)
      }
    }
  }

  /**
   * ```
   * AlgorithmIdentifier ::=  SEQUENCE  {
   *   algorithm  OBJECT IDENTIFIER,
   *   parameters ANY DEFINED BY algorithm OPTIONAL
   * }
   * ```
   */
  data class AlgorithmIdentifier(
    val algorithm: String,
    val parameters: AnyValue?
  ) {
    companion object {
      val ADAPTER = DerSequenceAdapter(
          members = listOf(
              DerAdapter.OBJECT_IDENTIFIER,
              AnyValue.ADAPTER.copy(isOptional = true, defaultValue = null)
          )
      ) {
        AlgorithmIdentifier(it[0] as String, it[1] as AnyValue?)
      }
    }
  }

  private fun date(s: String): Date {
    val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ").apply {
      timeZone = TimeZone.getTimeZone("GMT")
    }
    return format.parse(s)
  }
}
