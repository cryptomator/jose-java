package org.cryptomator.jose.util;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.TypedArgumentConverter;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@ConvertWith(Hex.Converter.class)
public @interface Hex {

	class Converter extends TypedArgumentConverter<String, byte[]> {

		protected Converter() {
			super(String.class, byte[].class);
		}

		@Override
		public byte[] convert(String source) throws ArgumentConversionException {
			try {
				return BaseEncoding.base16().ignoreCase().decode(source);
			} catch (IllegalArgumentException e) {
				throw new ArgumentConversionException("Failed to decode hex string: " + source, e);
			}
		}

	}
}

