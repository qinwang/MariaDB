/* Copyright (c) 2011, 2013, Oracle and/or its affiliates. All rights reserved.
   Copyright (c) 2014 MariaDB Foundation

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include <my_global.h>
#include "item_inetfunc.h"

#include "my_net.h"

///////////////////////////////////////////////////////////////////////////

static const int IN_ADDR_SIZE= sizeof (in_addr);
static const int IN6_ADDR_SIZE= sizeof (in6_addr);
static const int IN6_ADDR_NUM_WORDS= IN6_ADDR_SIZE / 2;

static const char HEX_DIGITS[]= "0123456789abcdef";

///////////////////////////////////////////////////////////////////////////

longlong Item_func_inet_aton::val_int()
{
  DBUG_ASSERT(fixed);

  uint byte_result= 0;
  ulonglong result= 0;                    // We are ready for 64 bit addresses
  const char *p,* end;
  char c= '.'; // we mark c to indicate invalid IP in case length is 0
  int dot_count= 0;

  StringBuffer<36> tmp;
  String *s= args[0]->val_str_ascii(&tmp);

  if (!s)       // If null value
    goto err;

  null_value= 0;

  end= (p = s->ptr()) + s->length();
  while (p < end)
  {
    c= *p++;
    int digit= (int) (c - '0');
    if (digit >= 0 && digit <= 9)
    {
      if ((byte_result= byte_result * 10 + digit) > 255)
        goto err;                               // Wrong address
    }
    else if (c == '.')
    {
      dot_count++;
      result= (result << 8) + (ulonglong) byte_result;
      byte_result= 0;
    }
    else
      goto err;                                 // Invalid character
  }
  if (c != '.')                                 // IP number can't end on '.'
  {
    /*
      Attempt to support short forms of IP-addresses. It's however pretty
      basic one comparing to the BSD support.
      Examples:
        127     -> 0.0.0.127
        127.255 -> 127.0.0.255
        127.256 -> NULL (should have been 127.0.1.0)
        127.2.1 -> 127.2.0.1
    */
    switch (dot_count) {
    case 1: result<<= 8; /* Fall through */
    case 2: result<<= 8; /* Fall through */
    }
    return (result << 8) + (ulonglong) byte_result;
  }

err:
  null_value=1;
  return 0;
}

///////////////////////////////////////////////////////////////////////////

String* Item_func_inet_ntoa::val_str(String* str)
{
  DBUG_ASSERT(fixed);

  ulonglong n= (ulonglong) args[0]->val_int();

  /*
    We do not know if args[0] is NULL until we have called
    some val function on it if args[0] is not a constant!

    Also return null if n > 255.255.255.255
  */
  if ((null_value= (args[0]->null_value || n > 0xffffffff)))
    return 0;                                   // Null value

  str->set_charset(collation.collation);
  str->length(0);

  uchar buf[8];
  int4store(buf, n);

  /* Now we can assume little endian. */

  char num[4];
  num[3]= '.';

  for (uchar *p= buf + 4; p-- > buf;)
  {
    uint c= *p;
    uint n1, n2;                                // Try to avoid divisions
    n1= c / 100;                                // 100 digits
    c-= n1 * 100;
    n2= c / 10;                                 // 10 digits
    c-= n2 * 10;                                // last digit
    num[0]= (char) n1 + '0';
    num[1]= (char) n2 + '0';
    num[2]= (char) c + '0';
    uint length= (n1 ? 4 : n2 ? 3 : 2);         // Remove pre-zero
    uint dot_length= (p <= buf) ? 1 : 0;
    (void) str->append(num + 4 - length, length - dot_length,
                       &my_charset_latin1);
  }

  return str;
}

///////////////////////////////////////////////////////////////////////////

/**
  Check the function argument, handle errors properly.

  @return The function value.
*/

longlong Item_func_inet_bool_base::val_int()
{
  DBUG_ASSERT(fixed);

  if (args[0]->result_type() != STRING_RESULT) // String argument expected
    return 0;

  String buffer;
  String *arg_str= args[0]->val_str(&buffer);

  if (!arg_str) // Out-of memory happened. The error has been reported.
    return 0;   // Or: the underlying field is NULL

  return calc_value(arg_str) ? 1 : 0;
}

///////////////////////////////////////////////////////////////////////////

/**
  Check the function argument, handle errors properly.

  @param [out] buffer Buffer for string operations.

  @return The function value.
*/

String *Item_func_inet_str_base::val_str_ascii(String *buffer)
{
  DBUG_ASSERT(fixed);

  if (args[0]->result_type() != STRING_RESULT) // String argument expected
  {
    null_value= true;
    return NULL;
  }

  String *arg_str= args[0]->val_str(buffer);
  if (!arg_str) // Out-of memory happened. The error has been reported.
  {             // Or: the underlying field is NULL
    null_value= true;
    return NULL;
  }

  null_value= !calc_value(arg_str, buffer);

  return null_value ? NULL : buffer;
}

///////////////////////////////////////////////////////////////////////////

/**
  Tries to convert given string to binary IPv4-address representation.
  This is a portable alternative to inet_pton(AF_INET).

  @param      str          String to convert.
  @param      str_len      String length.
  @param[out] ipv4_address Buffer to store IPv4-address.

  @return Completion status.
  @retval false Given string does not represent an IPv4-address.
  @retval true  The string has been converted sucessfully.

  @note The problem with inet_pton() is that it treats leading zeros in
  IPv4-part differently on different platforms.
*/

static bool str_to_ipv4(const char *str, int str_length, in_addr *ipv4_address)
{
  if (str_length < 7)
  {
    DBUG_PRINT("error", ("str_to_ipv4(%.*s): "
                         "invalid IPv4 address: too short.",
                         str_length, str));
    return false;
  }

  if (str_length > 15)
  {
    DBUG_PRINT("error", ("str_to_ipv4(%.*s): "
                         "invalid IPv4 address: too long.",
                         str_length, str));
    return false;
  }

  unsigned char *ipv4_bytes= (unsigned char *) ipv4_address;
  const char *p= str;
  int byte_value= 0;
  int chars_in_group= 0;
  int dot_count= 0;
  char c= 0;

  while (((p - str) < str_length) && *p)
  {
    c= *p++;

    if (my_isdigit(&my_charset_latin1, c))
    {
      ++chars_in_group;

      if (chars_in_group > 3)
      {
        DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                             "too many characters in a group.",
                             str_length, str));
        return false;
      }

      byte_value= byte_value * 10 + (c - '0');

      if (byte_value > 255)
      {
        DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                             "invalid byte value.",
                             str_length, str));
        return false;
      }
    }
    else if (c == '.')
    {
      if (chars_in_group == 0)
      {
        DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                             "too few characters in a group.",
                             str_length, str));
        return false;
      }

      ipv4_bytes[dot_count]= (unsigned char) byte_value;

      ++dot_count;
      byte_value= 0;
      chars_in_group= 0;

      if (dot_count > 3)
      {
        DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                             "too many dots.", str_length, str));
        return false;
      }
    }
    else
    {
      DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                           "invalid character at pos %d.",
                           str_length, str, (int) (p - str)));
      return false;
    }
  }

  if (c == '.')
  {
    DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                         "ending at '.'.", str_length, str));
    return false;
  }

  if (dot_count != 3)
  {
    DBUG_PRINT("error", ("str_to_ipv4(%.*s): invalid IPv4 address: "
                         "too few groups.",
                         str_length, str));
    return false;
  }

  ipv4_bytes[3]= (unsigned char) byte_value;

  DBUG_PRINT("info", ("str_to_ipv4(%.*s): valid IPv4 address: %d.%d.%d.%d",
                      str_length, str,
                      ipv4_bytes[0], ipv4_bytes[1],
                      ipv4_bytes[2], ipv4_bytes[3]));
  return true;
}

///////////////////////////////////////////////////////////////////////////

/**
  Tries to convert given string to binary IPv6-address representation.
  This is a portable alternative to inet_pton(AF_INET6).

  @param      str          String to convert.
  @param      str_len      String length.
  @param[out] ipv6_address Buffer to store IPv6-address.

  @return Completion status.
  @retval false Given string does not represent an IPv6-address.
  @retval true  The string has been converted sucessfully.

  @note The problem with inet_pton() is that it treats leading zeros in
  IPv4-part differently on different platforms.
*/

static bool str_to_ipv6(const char *str, int str_length, in6_addr *ipv6_address)
{
  if (str_length < 2)
  {
    DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: too short.",
                         str_length, str));
    return false;
  }

  if (str_length > 8 * 4 + 7)
  {
    DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: too long.",
                         str_length, str));
    return false;
  }

  memset(ipv6_address, 0, IN6_ADDR_SIZE);

  const char *p= str;

  if (*p == ':')
  {
    ++p;

    if (*p != ':')
    {
      DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                           "can not start with ':x'.", str_length, str));
      return false;
    }
  }

  char *ipv6_bytes= (char *) ipv6_address;
  char *ipv6_bytes_end= ipv6_bytes + IN6_ADDR_SIZE;
  char *dst= ipv6_bytes;
  char *gap_ptr= NULL;
  const char *group_start_ptr= p;
  int chars_in_group= 0;
  int group_value= 0;

  while (((p - str) < str_length) && *p)
  {
    char c= *p++;

    if (c == ':')
    {
      group_start_ptr= p;

      if (!chars_in_group)
      {
        if (gap_ptr)
        {
          DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                               "too many gaps(::).", str_length, str));
          return false;
        }

        gap_ptr= dst;
        continue;
      }

      if (!*p || ((p - str) >= str_length))
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "ending at ':'.", str_length, str));
        return false;
      }

      if (dst + 2 > ipv6_bytes_end)
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "too many groups (1).", str_length, str));
        return false;
      }

      dst[0]= (unsigned char) (group_value >> 8) & 0xff;
      dst[1]= (unsigned char) group_value & 0xff;
      dst += 2;

      chars_in_group= 0;
      group_value= 0;
    }
    else if (c == '.')
    {
      if (dst + IN_ADDR_SIZE > ipv6_bytes_end)
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "unexpected IPv4-part.", str_length, str));
        return false;
      }

      if (!str_to_ipv4(group_start_ptr,
                       str + str_length - group_start_ptr,
                       (in_addr *) dst))
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "invalid IPv4-part.", str_length, str));
        return false;
      }

      dst += IN_ADDR_SIZE;
      chars_in_group= 0;

      break;
    }
    else
    {
      const char *hdp= strchr(HEX_DIGITS, my_tolower(&my_charset_latin1, c));

      if (!hdp)
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "invalid character at pos %d.",
                             str_length, str, (int) (p - str)));
        return false;
      }

      if (chars_in_group >= 4)
      {
        DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                             "too many digits in group.",
                             str_length, str));
        return false;
      }

      group_value <<= 4;
      group_value |= hdp - HEX_DIGITS;

      DBUG_ASSERT(group_value <= 0xffff);

      ++chars_in_group;
    }
  }

  if (chars_in_group > 0)
  {
    if (dst + 2 > ipv6_bytes_end)
    {
      DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                           "too many groups (2).", str_length, str));
      return false;
    }

    dst[0]= (unsigned char) (group_value >> 8) & 0xff;
    dst[1]= (unsigned char) group_value & 0xff;
    dst += 2;
  }

  if (gap_ptr)
  {
    if (dst == ipv6_bytes_end)
    {
      DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                           "no room for a gap (::).", str_length, str));
      return false;
    }

    int bytes_to_move= dst - gap_ptr;

    for (int i= 1; i <= bytes_to_move; ++i)
    {
      ipv6_bytes_end[-i]= gap_ptr[bytes_to_move - i];
      gap_ptr[bytes_to_move - i]= 0;
    }

    dst= ipv6_bytes_end;
  }

  if (dst < ipv6_bytes_end)
  {
    DBUG_PRINT("error", ("str_to_ipv6(%.*s): invalid IPv6 address: "
                         "too few groups.", str_length, str));
    return false;
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////

/**
  Converts IPv4-binary-address to a string. This function is a portable
  alternative to inet_ntop(AF_INET).

  @param[in] ipv4 IPv4-address data (byte array)
  @param[out] str A buffer to store string representation of IPv4-address.
                  It must be at least of INET_ADDRSTRLEN.

  @note The problem with inet_ntop() is that it is available starting from
  Windows Vista, but the minimum supported version is Windows 2000.
*/

static void ipv4_to_str(const in_addr *ipv4, char *str)
{
  const unsigned char *ipv4_bytes= (const unsigned char *) ipv4;

  sprintf(str, "%d.%d.%d.%d",
          ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]);
}
///////////////////////////////////////////////////////////////////////////

/**
  Converts IPv6-binary-address to a string. This function is a portable
  alternative to inet_ntop(AF_INET6).

  @param[in] ipv6 IPv6-address data (byte array)
  @param[out] str A buffer to store string representation of IPv6-address.
                  It must be at least of INET6_ADDRSTRLEN.

  @note The problem with inet_ntop() is that it is available starting from
  Windows Vista, but out the minimum supported version is Windows 2000.
*/

static void ipv6_to_str(const in6_addr *ipv6, char *str)
{
  struct Region
  {
    int pos;
    int length;
  };

  const unsigned char *ipv6_bytes= (const unsigned char *) ipv6;

  // 1. Translate IPv6-address bytes to words.
  // We can't just cast to short, because it's not guaranteed
  // that sizeof (short) == 2. So, we have to make a copy.

  uint16 ipv6_words[IN6_ADDR_NUM_WORDS];

  for (int i= 0; i < IN6_ADDR_NUM_WORDS; ++i)
    ipv6_words[i]= (ipv6_bytes[2 * i] << 8) + ipv6_bytes[2 * i + 1];

  // 2. Find "the gap" -- longest sequence of zeros in IPv6-address.

  Region gap= { -1, -1 };

  {
    Region rg= { -1, -1 };

    for (int i = 0; i < IN6_ADDR_NUM_WORDS; ++i)
    {
      if (ipv6_words[i] != 0)
      {
        if (rg.pos >= 0)
        {
          if (rg.length > gap.length)
            gap= rg;

          rg.pos= -1;
          rg.length= -1;
        }
      }
      else
      {
        if (rg.pos >= 0)
        {
          ++rg.length;
        }
        else
        {
          rg.pos= i;
          rg.length= 1;
        }
      }
    }

    if (rg.pos >= 0)
    {
      if (rg.length > gap.length)
        gap= rg;
    }
  }

  // 3. Convert binary data to string.

  char *p= str;

  for (int i = 0; i < IN6_ADDR_NUM_WORDS; ++i)
  {
    if (i == gap.pos)
    {
      // We're at the gap position. We should put trailing ':' and jump to
      // the end of the gap.

      if (i == 0)
      {
        // The gap starts from the beginning of the data -- leading ':'
        // should be put additionally.

        *p= ':';
        ++p;
      }

      *p= ':';
      ++p;

      i += gap.length - 1;
    }
    else if (i == 6 && gap.pos == 0 &&
             (gap.length == 6 ||                           // IPv4-compatible
              (gap.length == 5 && ipv6_words[5] == 0xffff) // IPv4-mapped
             ))
    {
      // The data represents either IPv4-compatible or IPv4-mapped address.
      // The IPv6-part (zeros or zeros + ffff) has been already put into
      // the string (str). Now it's time to dump IPv4-part.

      ipv4_to_str((const in_addr *) (ipv6_bytes + 12), p);
      return;
    }
    else
    {
      // Usual IPv6-address-field. Print it out using lower-case
      // hex-letters without leading zeros (recommended IPv6-format).
      //
      // If it is not the last field, append closing ':'.

      p += sprintf(p, "%x", ipv6_words[i]);

      if (i != IN6_ADDR_NUM_WORDS - 1)
      {
        *p= ':';
        ++p;
      }
    }
  }

  *p= 0;
}

///////////////////////////////////////////////////////////////////////////

/**
  Converts IP-address-string to IP-address-data.

  @param       arg    IP-address-string.
  @param [out] buffer Buffer to store IP-address-data.

  @return Completion status.
  @retval false Given string does not represent an IP-address.
  @retval true  The string has been converted sucessfully.
*/

bool Item_func_inet6_aton::calc_value(String *arg, String *buffer)
{
  // ipv4-string -> varbinary(4)
  // ipv6-string -> varbinary(16)

  in_addr ipv4_address;
  in6_addr ipv6_address;

  if (str_to_ipv4(arg->ptr(), arg->length(), &ipv4_address))
  {
    buffer->length(0);
    buffer->append((char *) &ipv4_address, sizeof (in_addr), &my_charset_bin);

    return true;
  }

  if (str_to_ipv6(arg->ptr(), arg->length(), &ipv6_address))
  {
    buffer->length(0);
    buffer->append((char *) &ipv6_address, sizeof (in6_addr), &my_charset_bin);

    return true;
  }

  return false;
}

///////////////////////////////////////////////////////////////////////////

/**
  Converts IP-address-data to IP-address-string.

  @param       arg    IP-address-data.
  @param [out] buffer Buffer to store IP-address-string.

  @return Completion status.
  @retval false The argument does not correspond to IP-address.
  @retval true  The string has been converted sucessfully.
*/

bool Item_func_inet6_ntoa::calc_value(String *arg, String *buffer)
{
  if (arg->charset() != &my_charset_bin)
    return false;

  if ((int) arg->length() == IN_ADDR_SIZE)
  {
    char str[INET_ADDRSTRLEN];

    ipv4_to_str((const in_addr *) arg->ptr(), str);

    buffer->length(0);
    buffer->append(str, (uint32) strlen(str), &my_charset_latin1);

    return true;
  }
  else if ((int) arg->length() == IN6_ADDR_SIZE)
  {
    char str[INET6_ADDRSTRLEN];

    ipv6_to_str((const in6_addr *) arg->ptr(), str);

    buffer->length(0);
    buffer->append(str, (uint32) strlen(str), &my_charset_latin1);

    return true;
  }

  DBUG_PRINT("info",
             ("INET6_NTOA(): varbinary(4) or varbinary(16) expected."));
  return false;
}

///////////////////////////////////////////////////////////////////////////

/**
  Checks if the passed string represents an IPv4-address.

  @param arg The string to check.

  @return Check status.
  @retval false The passed string does not represent an IPv4-address.
  @retval true  The passed string represents an IPv4-address.
*/

bool Item_func_is_ipv4::calc_value(const String *arg)
{
  in_addr ipv4_address;

  return str_to_ipv4(arg->ptr(), arg->length(), &ipv4_address);
}

///////////////////////////////////////////////////////////////////////////

/**
  Checks if the passed string represents an IPv6-address.

  @param arg The string to check.

  @return Check status.
  @retval false The passed string does not represent an IPv6-address.
  @retval true  The passed string represents an IPv6-address.
*/

bool Item_func_is_ipv6::calc_value(const String *arg)
{
  in6_addr ipv6_address;

  return str_to_ipv6(arg->ptr(), arg->length(), &ipv6_address);
}

///////////////////////////////////////////////////////////////////////////

/**
  Checks if the passed IPv6-address is an IPv4-compat IPv6-address.

  @param arg The IPv6-address to check.

  @return Check status.
  @retval false The passed IPv6-address is not an IPv4-compatible IPv6-address.
  @retval true  The passed IPv6-address is an IPv4-compatible IPv6-address.
*/

bool Item_func_is_ipv4_compat::calc_value(const String *arg)
{
  if ((int) arg->length() != IN6_ADDR_SIZE || arg->charset() != &my_charset_bin)
    return false;

  return IN6_IS_ADDR_V4COMPAT((struct in6_addr *) arg->ptr());
}

///////////////////////////////////////////////////////////////////////////

/**
  Checks if the passed IPv6-address is an IPv4-mapped IPv6-address.

  @param arg The IPv6-address to check.

  @return Check status.
  @retval false The passed IPv6-address is not an IPv4-mapped IPv6-address.
  @retval true  The passed IPv6-address is an IPv4-mapped IPv6-address.
*/

bool Item_func_is_ipv4_mapped::calc_value(const String *arg)
{
  if ((int) arg->length() != IN6_ADDR_SIZE || arg->charset() != &my_charset_bin)
    return false;

  return IN6_IS_ADDR_V4MAPPED((struct in6_addr *) arg->ptr());
}


/**************************************************************************/
#include "sql_class.h"
#include "sql_time.h"

#define ASSERT_COLUMN_MARKED_FOR_READ DBUG_ASSERT(!table || (!table->read_set || bitmap_is_set(table->read_set, field_index)))
#define ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED DBUG_ASSERT(is_stat_field || !table || (!table->write_set || bitmap_is_set(table->write_set, field_index) || (table->vcol_set && bitmap_is_set(table->vcol_set, field_index))))


/* 2 power 64, in my_decimal format */
class my_decimal_2p64: public my_decimal
{
public:
 my_decimal_2p64()
 {
   my_decimal tmp; // 2 power 32
   int2my_decimal(E_DEC_FATAL_ERROR, 0x100000000ULL, true, &tmp);
   my_decimal_mul(E_DEC_FATAL_ERROR, this, &tmp, &tmp);
 }
};


static my_decimal_2p64 my_2p64;


static String ipv6_min("::", 2, &my_charset_latin1);


/**
  INET6 non-virtual definitions that are shared between
  Field_inet6, Item_typecast_inet6, Item_cache_inet6, Arg_comparator_inet6.
*/
class Type_handler_inet6_static_definitions
{
protected:

  class DTCollation_inet6: public DTCollation
  {
  public:
    DTCollation_inet6()
     :DTCollation(&my_charset_latin1, DERIVATION_NUMERIC, MY_REPERTOIRE_ASCII)
    { }
  };

  static Name type_name() { return Name(C_STRING_WITH_LEN("inet6")); }
  static enum_field_types field_type() { return (enum_field_types) 128; }
  static Item_result result_type () { return STRING_RESULT; }
  static enum Item_result cmp_type () { return STRING_RESULT; }
  static enum Item_result cast_to_int_type () { return DECIMAL_RESULT; }
  static uint binary_length() { return 16; }
  /**
    Non-abbreviated syntax is 8 groups, up to 4 digits each,
    plus 7 delimiters between the groups.
    Abbreviated syntax is even shorter.
  */
  static uint char_length() { return 8 * 4 + 7; }

  static void truncated_fraction_warning(const ErrConv &err)
  {
    // Fractional digits were truncated, send a note.
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_NOTE,
                        ER_UNKNOWN_ERROR,
                        "Cast to INET6 truncated fractional digits from '%s'",
                        err.ptr());
  }
  static void truncated_value_warning(const ErrConv &err, const char *value)
  {
    push_warning_printf(current_thd, Sql_condition::WARN_LEVEL_WARN,
                        ER_UNKNOWN_ERROR,
                        "Cast to INET6 converted '%s' to '%s'",
                        err.ptr(), value);
  }
  static void truncated_value_warning(const ErrConv &err, bool to_max)
  {
    truncated_value_warning(err,
                           !to_max ?
                           "::" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
  }
  static void set_min_value(char *to)
  {
    memset(to, 0x00, binary_length());
  }
  static void set_max_value(char *to)
  {
    memset(to, 0xFF, binary_length());
  }
  static void set_min_value_with_warn(char *to, const ErrConv &err)
  {
    set_min_value(to);
    truncated_value_warning(err, false);
  }
  static void set_max_value_with_warn(char *to, const ErrConv &err)
  {
    set_max_value(to);
    truncated_value_warning(err, true);
  }
  static bool set_truncated_value_with_warn(String *to,
                                            const ErrConv &err, bool to_max)
  {
    if (to->alloc(binary_length()))
      return true;
    truncated_value_warning(err, to_max);
    if (to_max)
      set_max_value((char *) to->ptr());
    else
      set_min_value((char *) to->ptr());
    to->length(binary_length());
    return false;
  }

  /*** Int type conversion routines ***/
  static void int_to_raw(ulonglong tmp, char *to)
  {
    memset(to, 0, 8);
    mi_int8store(to + 8, tmp);
  }

  static bool int_to_raw(ulonglong tmp, String *to)
  {
    if (to->alloc(binary_length()))
      return true;
    int_to_raw(tmp, (char *) to->ptr());
    to->length(binary_length());
    return false;
  }

  static bool int_to_raw(longlong tmp, bool unsigned_val, String *to)
  {
    return (tmp < 0 && !unsigned_val) ?
      set_truncated_value_with_warn(to, ErrConvInteger(tmp), false) :
      int_to_raw((ulonglong) tmp, to);
  }

  static longlong raw_to_int(const char *raw)
  {
    longlong i;
    my_decimal tmp;
    my_decimal2int(E_DEC_FATAL_ERROR, raw_to_decimal(raw, &tmp),
                   true, &i);
    return i;
  }

  static bool raw_to_int(const String *raw, longlong *to)
  {
    DBUG_ASSERT(raw->length() == binary_length());
    *to= raw_to_int(raw->ptr());
    return false;
  }

  /*** Real type conversion routines ***/
  static bool real_to_raw(double nr, String *to)
  {
    my_decimal dec;
    return (nr < 0 ||
            double2my_decimal(E_DEC_FATAL_ERROR & ~E_DEC_OVERFLOW, nr, &dec)) ?
      set_truncated_value_with_warn(to, ErrConvDouble(nr), nr > 0) :
      decimal_to_raw(&dec, to);
  }

  static double raw_to_real(const char *raw)
  {
    return (double) mi_uint8korr(raw) * (double) 0x100000000ULL +
           (double) mi_uint8korr(raw + 8);
  }

  static bool raw_to_real(const String *raw, double *to)
  {
    DBUG_ASSERT(raw->length() == binary_length());
    *to= raw_to_real(raw->ptr());
    return false;
  }

  /*** Decimal type conversion routines ***/
  static bool decimal_to_raw(const my_decimal *num, String *to)
  {
    longlong tmp;
    my_decimal dec;
    /* Store the high 8 bytes */
    my_decimal_div(E_DEC_FATAL_ERROR, &dec, num, &my_2p64, 0);
    my_decimal_round(E_DEC_FATAL_ERROR, &dec, 0, true, &dec);
    if (my_decimal2int(0, &dec, true, &tmp))
      return set_truncated_value_with_warn(to, ErrConvDecimal(num), !dec.sign());
    if (to->alloc(binary_length()))
      return true;
    mi_int8store((char*) to->ptr(), tmp);
    /* Store the low 8 bytes */
    my_decimal_mod(E_DEC_FATAL_ERROR, &dec, num, &my_2p64);
    if (!my_decimal2int(E_DEC_FATAL_ERROR, &dec, true, &tmp) &&
        decimal_actual_fraction(num) > 0)
      truncated_fraction_warning(ErrConvDecimal(num));
    mi_int8store((char *) to->ptr() + 8, tmp);
    to->length(binary_length());
    return false;
  }

  static my_decimal *raw_to_decimal(const char *raw, my_decimal *to)
  {
    my_decimal a, b;
    int2my_decimal(E_DEC_FATAL_ERROR, mi_uint8korr(raw), true, &a);
    my_decimal_mul(E_DEC_FATAL_ERROR, &b, &a, &my_2p64);
    int2my_decimal(E_DEC_FATAL_ERROR, mi_uint8korr(raw + 8), true, &a);
    my_decimal_add(E_DEC_FATAL_ERROR, to, &b, &a);
    return to;
  }

  static bool raw_to_decimal(const String *raw, my_decimal *to)
  {
    DBUG_ASSERT(raw->length() == binary_length());
    raw_to_decimal(raw->ptr(), to);
    return false;
  }

  /*** String type conversion routines ***/
  static bool str_to_ipv6(const char *str, int str_length, char *ipv6)
  {
    return ::str_to_ipv6(str, str_length, (in6_addr *) ipv6);
  }

  static void ipv6_to_str(const char *ipv6, char *str)
  {
    ::ipv6_to_str((const in6_addr*) ipv6, str);
  }

  static bool ipv6_to_str(const char *ipv6, String *str)
  {
    if (str->alloc(INET6_ADDRSTRLEN))
      return true;
    ipv6_to_str(ipv6, const_cast<char*>(str->ptr()));
    uint length= (uint) strlen(str->ptr());
    str->length(length);
    str->set_charset(&my_charset_numeric);
    return false;
  }

  static bool str_to_raw(const String *from, String *to)
  {
    if (to->alloc(binary_length()))
      return true;
    if (!str_to_ipv6(from->ptr(), from->length(), (char*) to->ptr()))
      set_min_value_with_warn((char *) to->ptr(), ErrConvString(from));
    to->length(binary_length());
    to->set_charset(&my_charset_bin);
    return false;
  }

  static bool hex_hybrid_str_to_raw(const String *from, String *to)
  {
    if (to->alloc(binary_length()))
      return true;
    to->length(binary_length());
    int diff= from->length() - binary_length();
    if (!diff)
    {
      memcpy((char *) to->ptr(), from->ptr(), from->length());
    }
    else if (diff > 0) // The value is longer than INET6 binary size
    {
      memcpy((char *) to->ptr(), from->ptr() + diff, from->length() - diff);
      StringBuffer<64> buf;
      raw_to_str(to, &buf);
      truncated_value_warning(ErrConvString(from), buf.c_ptr());
    }
    else // The value is shorter
    {
      memset((char *) to->ptr(), 0x00, -diff);
      memcpy((char *) to->ptr() - diff, from->ptr(), from->length());
    }
    return false;
  }
  static bool raw_to_str(const String *raw, String *to)
  {
    DBUG_ASSERT(raw->length() == binary_length());
    return ipv6_to_str(raw->ptr(), to);
  }

  /*** Temporal type conversion routines ***/
  static bool date_to_raw(const MYSQL_TIME *ltime, String *to)
  {
    ulonglong tmp= TIME_to_ulonglong(ltime);
    if (ltime->neg && (tmp || ltime->second_part))
      return set_truncated_value_with_warn(to, ErrConvTime(ltime), false);
    if (ltime->second_part > 0)
      truncated_fraction_warning(ErrConvTime(ltime));
    return int_to_raw(tmp, to);
  }

  static bool raw_to_date(const char *raw,
                          MYSQL_TIME *ltime, ulonglong fuzzydate)
  {
    my_decimal tmp;
    return decimal_to_datetime_with_warn(raw_to_decimal(raw, &tmp),
                                         ltime, fuzzydate, NULL);
  }

  static bool raw_to_date(const String *raw,
                          MYSQL_TIME *ltime, ulonglong fuzzydate)
  {
    DBUG_ASSERT(raw->length() == binary_length());
    return raw_to_date(raw->ptr(), ltime, fuzzydate);
  }

  /**
    Item conversion routines: val_xxx_from_val_raw().
    The "item" variable can be of any data type, not necessarily INET6,
    for example in a query like this:
      SELECT CAST(CAST('ff::ff' AS INET6) AS DOUBLE);
    "item" will be a pointer to Item_string, with is MYSQL_TYPE_VARCHAR.

    We do two conversion operations in every val_xxx_from_val_raw() method.

    1. Convert from the source type to INET6 optionally,
       if the data type of "item" is not INET6.
       In the above example the string 'ff:ff' is converted to INET6.

    2. Convert to the destination type from INET6
  */
  static String *val_str_from_val_raw(Item *item, String *buf)
  {
    StringBuffer<64> tmpbuf;
    String *tmp;
    if (!(tmp= val_raw_with_optional_conversion(item, &tmpbuf)) ||
        tmp->length() != binary_length() ||
        raw_to_str(tmp, buf))
      return ((item->null_value= item->maybe_null)) ? 0 : &ipv6_min;
    item->null_value= false;
    return buf;
  }
  static double val_real_from_val_raw(Item *item)
  {
    StringBuffer<64> tmpbuf;
    String *tmp;
    double res;
    if (!(tmp= val_raw_with_optional_conversion(item, &tmpbuf)) ||
        tmp->length() != binary_length() ||
        raw_to_real(tmp, &res))
    {
      item->null_value= item->maybe_null;
      return 0;
    }
    return res;
  }
  static longlong val_int_from_val_raw(Item *item)
  {
    StringBuffer<64> tmpbuf;
    String *tmp;
    longlong res;
    if (!(tmp= val_raw_with_optional_conversion(item, &tmpbuf)) ||
        tmp->length() != binary_length() ||
        raw_to_int(tmp, &res))
    {
      item->null_value= item->maybe_null;
      return 0;
    }
    item->null_value= false;
    return res;
  }
  static my_decimal *val_decimal_from_val_raw(Item *item, my_decimal *buf)
  {
    StringBuffer<64> tmpbuf;
    String *tmp;
    if (!(tmp= val_raw_with_optional_conversion(item, &tmpbuf)) ||
        tmp->length() != binary_length())
    {
      if ((item->null_value= item->maybe_null))
        return 0;
      raw_to_decimal(tmp, buf);
      return buf;
    }
    item->null_value= false;
    return raw_to_decimal(tmp->ptr(), buf);
  }
  /*
    TODO: we don't allow mixing of INET6 and temporal types for
    hybrid result functions, comparison, UNION.
    Perhaps mutual direct explicit or implicit cast should also be disallowed:
      SELECT CAST(inet6_expr AS TIME);
      SELECT CAST(time_expr AS INET6);
    So should all other queries involving type conversion:
      ALTER TABLE t1 MODIFY inet6_column TIME;
      ALTER TABLE t1 MODIFY time_column INET6;
      INSERT INTO t1 (inet6_column) SELECT time_expression...;
      INSERT INTO t1 (time_column) SELECT inet6_expression...;
    Note, for all above queries we should return errors during fix_fields()
    rather than execution time.
    We'll need some infrastructure to check if data types are OK in various
    contexts, like CAST, ALTER, INSERT/SET, etc.
  */
  static bool get_date_from_val_raw(Item *item,
                                    MYSQL_TIME *ltime,
                                    ulonglong fuzzydate)
  {
    StringBuffer<64> tmpbuf;
    String *tmp;
    if (!(tmp= val_raw_with_optional_conversion(item, &tmpbuf)) ||
        tmp->length() != binary_length() ||
        raw_to_date(tmp, ltime, fuzzydate))
    {
      bzero(ltime, sizeof(*ltime));
      return (item->null_value= item->maybe_null);
    }
    return (item->null_value= false);
  }


  /*** Item conversion routines: val_raw_from_xxx ********************/
  /**
    QQ: If to->alloc() fails inside hex_hybrid_str_to_raw(), then it will
    return NULL, which can contradict with item->maybe_null.
    What is the proper way to handle this?
  */
  static bool val_raw_from_hex_hybrid(Item *item, String *to)
  {
    StringBuffer<64> buf;
    String *tmp;
    if (!(tmp= item->val_str(&buf)))
      return item->null_value= true;
    return item->null_value= hex_hybrid_str_to_raw(tmp, to);
  }

  static bool val_raw_from_val_str(Item *item, String *to)
  {
    StringBuffer<64> buf;
    String *tmp;
    if (!(tmp= item->val_str(&buf)))
      return item->null_value= true;
    return item->null_value= str_to_raw(tmp, to);
  }

  static bool val_raw_from_val_decimal(Item *item, String *to)
  {
    my_decimal buf, *num;
    if (!(num= item->val_decimal(&buf)))
      return item->null_value= true;
    return item->null_value= decimal_to_raw(num, to);
  }

  static bool val_raw_from_val_int(Item *item, String *to)
  {
    longlong tmp= item->val_int();
    if (item->null_value)
      return true;
    return item->null_value= int_to_raw(tmp, item->unsigned_flag, to);
  }

  static bool val_raw_from_val_real(Item *item, String *to)
  {
    double tmp= item->val_real();
    if (item->null_value)
      return true;
    return item->null_value= real_to_raw(tmp, to);
  }

  static bool val_raw_from_get_date(Item *item, String *to)
  {
    MYSQL_TIME ltime;
    if (item->get_date(&ltime, item->field_type() == MYSQL_TYPE_TIME ?
                               TIME_TIME_ONLY : 0))
      return true;
    return item->null_value= date_to_raw(&ltime, to);
  }

  // TODO: check that all callers use the return value rather than "to"
  static String *val_raw_with_conversion(Item *item, String *to)
  {
    switch (item->cmp_type())
    {
    case STRING_RESULT:
      return val_raw_from_val_str(item, to) ? 0 : to;
    case INT_RESULT:
      return val_raw_from_val_int(item, to) ? 0 : to;
    case REAL_RESULT:
      return val_raw_from_val_real(item, to) ? 0 : to;
    case TIME_RESULT:
      return val_raw_from_get_date(item, to) ? 0 : to;
    case DECIMAL_RESULT:
      return val_raw_from_val_decimal(item, to) ? 0 : to;
    case ROW_RESULT:
      break;
    }
    DBUG_ASSERT(0);
    item->null_value= true;
    return 0;
  }

  /**
    Convert "item" to INET6.
    For the cases when "item" is known not to be Item_hex_hybrid,
    so conversion from string to INET6 is always done in text format.
  */
  static String *val_raw_with_optional_conversion(Item *item, String *to)
  {
    return item->field_type() == field_type() ?
           item->val_raw_native(to) :
           val_raw_with_conversion(item, to);
  }

  /**
    Convert "item" to INET6 using handler.
    For the case when "item" can be Item_hex_hybrid.
    "handler" needs to be passed to item->val_raw().
    - Item_hex_hybrid::val_raw() will call Item_hex_hybrid_val_raw().
    - Item::val_raw() will call Item_val_raw().
  */
  static String *val_raw_with_optional_conversion(const Type_handler *handler,
                                                  Item *item, String *to)
  {
    return item->field_type() == field_type() ?
           item->val_raw_native(to) :
           item->val_raw(handler, to);
  }

  static int cmp_raw(const String *a, const String *b)
  {
    DBUG_ASSERT(a->length() == binary_length());
    DBUG_ASSERT(b->length() == binary_length());
    return memcmp(a->ptr(), b->ptr(), binary_length());
  }

};


class Type_handler_inet6: public Type_handler,
                          private Type_handler_inet6_static_definitions
{
public:
  Type_handler_inet6()
  { }
  ~Type_handler_inet6() {}

  const Name type_name() const
  {
    return Type_handler_inet6_static_definitions::type_name();
  }
  enum_field_types field_type() const
  {
    return Type_handler_inet6_static_definitions::field_type();
  }
  Item_result result_type () const
  {
    return Type_handler_inet6_static_definitions::result_type();
  }
  enum Item_result cmp_type () const
  {
    return Type_handler_inet6_static_definitions::cmp_type();
  }
  enum Item_result cast_to_int_type () const
  {
    return Type_handler_inet6_static_definitions::cast_to_int_type();
  }

  bool is_blob_field_type() const { return false; };
  bool is_fixed_length_binary_type() const { return true; }

  bool check_column_definition(THD *thd, Column_definition *definition) const
  {
    DBUG_ASSERT(!definition->vcol_info);
    if (definition->flags & AUTO_INCREMENT_FLAG)
    {
      my_error(ER_WRONG_FIELD_SPEC, MYF(0), definition->field_name);
      return true;
    }
    if (definition->def)
    {
      if (definition->def->type() == Item::FUNC_ITEM)
      {
        my_error(ER_INVALID_DEFAULT, MYF(0), definition->field_name);
        return true;
      }
      if (definition->def->type() == Item::NULL_ITEM)
        definition->def= 0;
    }
    if (definition->on_update)
    {
      my_error(ER_INVALID_ON_UPDATE, MYF(0), definition->field_name);
      return true;
    }
    // prepare_blob_field() needs "char_length" not to be set to a long value
    definition->char_length= 0;
    return false;
  }

  bool prepare_column_definition(Column_definition *sql_field,
                                 longlong table_flags) const
  {
    sql_field->pack_flag= f_settype((uint) sql_field->sql_type);
    return false;
  }

  Field *make_table_field(MEM_ROOT *mem_root,
                          TABLE_SHARE *share,
                          const char *field_name,
                          const Record_addr &rec,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_num_distinct_aggregator_field(MEM_ROOT *,
                                            const Item *) const;
  Field *make_conversion_table_field(TABLE *table, uint metadata,
                                     const Field *target) const;

  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const
  {
    if (field->type() == Type_handler_inet6::field_type())
    {
      StringBuffer<MAX_FIELD_WIDTH> tmp;
      String *str= item->val_raw_native(&tmp);
      if (item->null_value)
        return set_field_to_null_with_conversions(field, no_conversions);
      field->set_notnull();
      return field->store_raw_native(str->ptr(), str->length());
    }
    /*
      Get a standard handler, according to field->result_type().
      For example,
        INSERT INTO t1 (int_field) VALUES (COALESCE(inet6_expr));
      will effectively do field->store(item->val_int()).
    */
    Type_handler_hybrid_field_type handler(field->result_type());
    return handler.Item_save_in_field(item, field, no_conversions);
  }

  Item_cache *make_cache_item(THD *thd, const Item *item) const;

  Item *make_typecast_item(THD *thd, Item *arg) const;

  void make_sort_key(uchar *to, Item *item,
                     const SORT_FIELD_ATTR *sort_field,
                     Sort_param *param) const
  {
    StringBuffer<128> tmp;
    DBUG_ASSERT(item->field_type() == Type_handler_inet6::field_type());
    item->val_raw_native_result(&tmp);
    if (item->maybe_null)
    {
      if (item->null_value)
      {
        memset(to, 0, binary_length() + 1);
        return;
      }
      *to++= 1;
    }
    DBUG_ASSERT(!item->null_value);
    DBUG_ASSERT(binary_length() == tmp.length());
    DBUG_ASSERT(binary_length() == sort_field->length);
    memcpy(to, tmp.ptr(), binary_length());
  }
  void sortlength(THD *thd, const Type_std_attributes *item,
                  SORT_FIELD_ATTR *attr) const
  {
    attr->length= binary_length();
    attr->suffix_length= 0;
  }

  uint32 calc_pack_length(uint32 length) const
  {
    return binary_length();
  }

  uint32 calc_display_length(const Type_std_attributes *attr) const
  {
    return char_length();
  }

  bool join_type_attributes(Type_std_attributes *std_attr,
                            Type_ext_attributes *ext_attr,
                            Item **item, uint nitems) const
  {
    *std_attr= Type_std_attributes(DTCollation_inet6(), char_length());
    return false;
  }

  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const
  {
    *(static_cast<Type_std_attributes*>(holder))=
      Type_std_attributes(DTCollation_inet6(), char_length());
    return false;
  }
  bool set_comparator_func(Arg_comparator *cmp) const;

  int cmp_raw(const String *a, const String *b) const
  {
    return Type_handler_inet6_static_definitions::cmp_raw(a, b);
  }

  /*
  TODO:
  MDEV-9395 Add Type_handler::temporal_scale() and Type_handler::decimal_scale()

  "max_length" of an INET6-type item is set to 8 * 4 + 7 = 39.
  (see Type_handler_inet6_static_definitions::char_length()),
  and "decimals" is set to 0 by default.

  In a coincedence, decimal precision of INET6 is also 39 digits:
    'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' =
     340282366920938463463374607431768211456  = 39 digits

  Therefore, we don't need these Type_handler methods
  for INET6 purposes urgently, but they should be added eventually:
  uint decimal_precision(const Type_std_attributes *attr) const { return 39; }
  uint decimal_scale(const Type_std_attributes *attr) const { return 0; }
  }
  */

  String *Item_func_hex_val_str_ascii(Item_func_hex *item, String *to) const
  {
    return item->val_str_ascii_from_val_raw_native(to);
  }
  String *Item_hex_hybrid_val_raw(Item_hex_hybrid *item, String *to) const
  {
    return val_raw_from_hex_hybrid(item, to) ? 0 : to;
  }
  String *Item_val_raw(Item *item, String *str) const
  {
    return val_raw_with_optional_conversion(item, str);
  }
  String *Item_val_str(Item *item, String *str) const
  {
    return val_str_from_val_raw(item, str);
  }
  longlong Item_val_int(Item *item) const
  {
    return val_int_from_val_raw(item);
  }
  double Item_val_real(Item *item) const
  {
    return val_real_from_val_raw(item);
  }
  my_decimal* Item_val_decimal(Item *item, my_decimal *to) const
  {
    return val_decimal_from_val_raw(item, to);
  }
  bool Item_get_date(Item *item, MYSQL_TIME *ltime, ulonglong fuzzy) const
  {
    return get_date_from_val_raw(item, ltime, fuzzy);
  }


  String *
  Item_func_hybrid_field_type_val_raw(Item_func_hybrid_field_type *item,
                                      String *str) const
  {
    return item->field_type() == Type_handler_inet6::field_type() ?
           item->raw_op(str) :
           val_raw_with_conversion(item, str);
  }
  String *
  Item_func_hybrid_field_type_val_str(Item_func_hybrid_field_type *item,
                                      String *str) const
  {
    return val_str_from_val_raw(item, str);
  }
  longlong
  Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const
  {
    return val_int_from_val_raw(item);
  }
  double
  Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const
  {
    return val_real_from_val_raw(item);
  }
  my_decimal*
  Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                          my_decimal *to) const
  {
    return val_decimal_from_val_raw(item, to);
  }
  bool
  Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                       MYSQL_TIME *ltime, ulonglong fuzzydate)
                                       const
  {
    return get_date_from_val_raw(item, ltime, fuzzydate);
  }

  longlong Item_func_between_val_int(Item_func_between *func) const;
  bool Item_func_between_fix_length_and_dec(Item_func_between *func) const
  {
    return false;
  }
  bool Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const
  {
    Item *item= func->arguments()[0];
    func->Type_std_attributes::set(item);
    func->set_handler_by_field_type(item->field_type());
    return false;
  }

};


/**
  A class whose instances automatically add themself into
  the data type registry.
*/
class Type_handler_inet6_singleton: public Type_handler_inet6
{
public:
  Type_handler_inet6_singleton()
  {
    Type_handlers.add(this, type_name());
  }
};


Type_handler_inet6_singleton type_handler_inet6_singleton;



class Field_inet6: public Field,
                   private Type_handler_inet6_static_definitions
{
  void store_warning(const ErrConv &str,
                     Sql_condition::enum_warning_level level)
  {
    push_warning_printf(get_thd(), level,
                        ER_TRUNCATED_WRONG_VALUE_FOR_FIELD,
                        ER(ER_TRUNCATED_WRONG_VALUE_FOR_FIELD),
                        type_name().ptr(), str.ptr(), field_name,
                        (ulong) table->in_use->get_stmt_da()->
                        current_row_for_warning());
  }
  int set_null_with_warn(const ErrConv &str)
  {
    store_warning(str, Sql_condition::WARN_LEVEL_WARN);
    set_null();
    return 1;
  }
  int set_min_value_with_warn(const ErrConv &str)
  {
    store_warning(str, Sql_condition::WARN_LEVEL_WARN);
    set_min_value((char*) ptr);
    return 1;
  }
  int set_max_value_with_warn(const ErrConv &str)
  {
    store_warning(str, Sql_condition::WARN_LEVEL_WARN);
    set_max_value((char*) ptr);
    return 1;
  }

public:
  Field_inet6(const char *field_name_arg, const Record_addr &rec)
    :Field(rec.ptr, Type_handler_inet6_static_definitions::char_length(),
           rec.null_ptr, rec.null_bit, Field::NONE, field_name_arg)
  {
    flags|= BINARY_FLAG | UNSIGNED_FLAG;
  }
  Item_result result_type () const
  {
    return Type_handler_inet6_static_definitions::result_type();
  }
  enum Item_result cmp_type () const
  {
    return Type_handler_inet6_static_definitions::cmp_type();
  }
  enum_field_types type() const
  {
    return Type_handler_inet6_static_definitions::field_type();
  }

  uint32 max_display_length() { return field_length; }
  bool str_needs_quotes() { return true; }
  enum Derivation derivation(void) const { return DERIVATION_NUMERIC; }
  uint repertoire(void) const { return MY_REPERTOIRE_NUMERIC; }
  CHARSET_INFO *charset(void) const { return &my_charset_numeric; }
  const CHARSET_INFO *sort_charset(void) const { return &my_charset_bin; }
  /**
    This makes client-server protocol convert the value according
    to @@character_set_client.
  */
  bool binary() const { return false; }
  enum Item_result cast_to_int_type() const { return DECIMAL_RESULT; }
  enum ha_base_keytype key_type() const { return HA_KEYTYPE_BINARY; }

  uint is_equal(Create_field *new_field)
  {
    return new_field->sql_type == real_type();
  }
  bool eq_def(const Field *field) const
  {
    return Field::eq_def(field);
  }
  double pos_in_interval(Field *min, Field *max)
  {
    return pos_in_interval_val_real(min, max);
  }
  int cmp(const uchar *a, const uchar *b)
  { return memcmp(a, b, pack_length()); }

  void sort_string(uchar *to, uint length)
  {
    DBUG_ASSERT(length == pack_length());
    memcpy(to, ptr, length);
  }
  uint32 pack_length() const
  {
    return Type_handler_inet6_static_definitions::binary_length();
  }

  void sql_type(String &str) const
  {
    str.set_ascii(type_name());
  }

/**
  These methods do not seem to need INET6-specific implementations:
    bool send_binary(Protocol *protocol);
    uchar *pack(uchar* to, const uchar *from,
                uint max_length __attribute__((unused)));
    const uchar *unpack(uchar* to, const uchar *from, const uchar *from_end,
                        uint param_data __attribute__((unused)));
*/

  bool validate_value_in_record(THD *thd, const uchar *record) const
  {
    return false;
  }

  String *val_str(String *val_buffer,
                  String *val_ptr __attribute__((unused)))
  {
    return ipv6_to_str((const char *) ptr, val_buffer) ? NULL : val_buffer;
  }

  my_decimal *val_decimal(my_decimal *to)
  {
    ASSERT_COLUMN_MARKED_FOR_READ;
    return raw_to_decimal((const char *) ptr, to);
  }

  longlong val_int()
  {
    ASSERT_COLUMN_MARKED_FOR_READ;
    return raw_to_int((const char *)ptr);
  }

  double val_real()
  {
    ASSERT_COLUMN_MARKED_FOR_READ;
    return raw_to_real((const char *) ptr);
  }

  bool get_date(MYSQL_TIME *ltime, ulonglong fuzzydate)
  {
    ASSERT_COLUMN_MARKED_FOR_READ;
    return raw_to_date((const char *)ptr, ltime, fuzzydate);
  }

  bool val_bool(void)
  {
    for (uint i= 0; i < binary_length(); i++)
    {
      if (ptr[i] != 0)
        return true;
    }
    return false;
  }

  int store_raw_native(const char *str, uint length)
  {
    DBUG_ASSERT(length == binary_length());
    memcpy(ptr, str, binary_length());
    return 0;
  }

  int store(const char *str, uint length, CHARSET_INFO *cs)
  {
    if (!str_to_ipv6(str, length, (char*) ptr))
    {
      return maybe_null() ?
             set_null_with_warn(ErrConvString(str, length, cs)) :
             set_min_value_with_warn(ErrConvString(str, length, cs));
    }
    return 0;
  }

  int store_hex_hybrid(const char *str, uint length)
  {
    String from(str, length, &my_charset_bin);
    StringBuffer<64> to;
    if (hex_hybrid_str_to_raw(&from, &to))
    {
      return maybe_null() ?
             set_null_with_warn(ErrConvString(from)) :
             set_min_value_with_warn(ErrConvString(from));
    }
    return store_raw_native(to.ptr(), to.length());
  }

  int store_decimal(const my_decimal *num)
  {
    ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED;
    longlong tmp;
    my_decimal dec;
    /* Store the high 8 bytes */
    my_decimal_div(E_DEC_FATAL_ERROR, &dec, num, &my_2p64, 0);
    my_decimal_round(E_DEC_FATAL_ERROR, &dec, 0, true, &dec);
    if (my_decimal2int(0, &dec, true, &tmp))
    {
      return dec.sign() ? set_min_value_with_warn(ErrConvDecimal(num)) :
                          set_max_value_with_warn(ErrConvDecimal(num));
    }
    mi_int8store(ptr, tmp);
    /* Store the low 8 bytes */
    my_decimal_mod(E_DEC_FATAL_ERROR, &dec, num,  &my_2p64);
    my_decimal2int(E_DEC_FATAL_ERROR, &dec, true, &tmp);
    mi_int8store(ptr + 8, tmp);
    if (decimal_actual_fraction(num) > 0)
    {
      truncated_fraction_warning(ErrConvDecimal(num));
      return 2;
    }
    return 0;
  }

  int store(longlong nr, bool unsigned_flag)
  {
    ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED;
    if (nr < 0 && !unsigned_flag)
      return set_min_value_with_warn(ErrConvInteger(nr));
    int_to_raw(nr, (char *) ptr);
    return 0;
  }

  int store(double nr)
  {
    ASSERT_COLUMN_MARKED_FOR_WRITE_OR_COMPUTED;
    if (nr < 0)
      return set_min_value_with_warn(ErrConvDouble(nr));
    my_decimal dec;
    if (double2my_decimal(E_DEC_FATAL_ERROR & ~E_DEC_OVERFLOW, nr, &dec))
      return set_max_value_with_warn(ErrConvDouble(nr));
    return store_decimal(&dec);
  }

  int store_time_dec(MYSQL_TIME *ltime, uint dec)
  {
    my_decimal tmp;
    return store_decimal(date2my_decimal(ltime, &tmp));
  }

  /*** Field conversion routines ***/
  int store_field(Field *from)
  {
    // INSERT INTO t1 (inet6_field) SELECT different_field_type FROM t2;
    return from->save_in_field(this);
  }
  int save_in_field(Field *to)
  {
    // INSERT INTO t2 (different_field_type) SELECT inet6_field FROM t1;
    switch (to->cmp_type()) {
    case INT_RESULT:
    case REAL_RESULT:
    case DECIMAL_RESULT:
    case TIME_RESULT:
    {
      my_decimal buff;
      return to->store_decimal(val_decimal(&buff));
    }
    case STRING_RESULT:
      return save_in_field_str(to);
    case ROW_RESULT:
      break;
    }
    DBUG_ASSERT(0);
    to->reset();
    return 0;
  }
  Copy_func *get_copy_func(const Field *from) const
  {
    // ALTER to INET6 from another field
    if (eq_def(from))
      return get_identical_copy_func();
    switch (from->cmp_type()) {
    case STRING_RESULT:
      return do_field_string;
    case TIME_RESULT:
      return do_field_temporal;
    case DECIMAL_RESULT:
      return do_field_decimal;
    case REAL_RESULT:
      return do_field_real;
    case INT_RESULT:
      return do_field_int;
    case ROW_RESULT:
      DBUG_ASSERT(0);
      break;
    }
    return do_field_string;
  }

  bool memcpy_field_possible(const Field *from) const
  {
    // INSERT INTO t1 (inet6_field) SELECT field2 FROM t2;
    return real_type() == from->real_type();
  }


  /*** Optimizer routines ***/
  bool test_if_equality_guarantees_uniqueness(const Item *const_item) const
  {
    /*
      This condition:
        WHERE inet6_field=const
      should return a single distinct value only,
      as comparison is done according to INET6.
      But we need to implement get_equal_const_item() first.
    */
    return false; // TODO: implement get_equal_const_item()
  }
  bool can_be_substituted_to_equal_item(const Context &ctx,
                                        const Item_equal *item)
  {
    return false; // TODO: equal field propagation
  }
  Item *get_equal_const_item(THD *thd, const Context &ctx,
                             Item *const_item)
  {
    /*
      This should return Item_inet6_literal (which is not implemented yet)
    */
    return NULL; // TODO: equal expression propagation
  }
  bool can_optimize_keypart_ref(const Item_bool_func *cond,
                                const Item *item) const
  {
    /*
      Mixing of two different non-traditional types is currently
      prevented in merge_type() and merge_type_for_comparison().
      This may change in the future. For example, INET4 and INET6
      data types can be made comparable.
    */
    DBUG_ASSERT(item->is_traditional_field_type() ||
                item->field_type() == field_type());
    return true;
  }
  /**
    Test if Field can use range optimizer for a standard comparison operation:
      <=, <, =, <=>, >, >=
    Note, this method does not cover spatial operations.
  */
  bool can_optimize_range(const Item_bool_func *cond,
                          const Item *item,
                          bool is_eq_func) const
  {
    // See the DBUG_ASSERT comment in can_optimize_keypart_ref()
    DBUG_ASSERT(item->is_traditional_field_type() ||
                item->field_type() == field_type());
    return true;
  }
  bool can_optimize_hash_join(const Item_bool_func *cond,
                                      const Item *item) const
  {
    return can_optimize_keypart_ref(cond, item);
  }
  bool can_optimize_group_min_max(const Item_bool_func *cond,
                                  const Item *const_item) const
  {
    return true;
  }

  /**********/
  uint size_of() const { return sizeof(*this); }
};


class Item_cache_inet6: public Item_cache,
                        private Type_handler_inet6_static_definitions
{
  char m_value[16];
  void reset_value() { bzero(m_value, sizeof(m_value)); }
public:
  Item_cache_inet6(THD *thd):
    Item_cache(thd, Type_handler_inet6_static_definitions::field_type())
  { reset_value(); }
  const Type_handler *type_handler() const
  { return &type_handler_inet6_singleton; }
  enum_field_types field_type() const
  { return Type_handler_inet6_static_definitions::field_type(); }
  Item_result result_type () const
  { return Type_handler_inet6_static_definitions::result_type(); }
  enum Item_result cmp_type () const
  { return Type_handler_inet6_static_definitions::cmp_type(); }
  enum Item_result cast_to_int_type () const
  { return Type_handler_inet6_static_definitions::cast_to_int_type(); }


  String *val_str(String *to)
  {
    return val_str_from_val_raw(this, to);
  }
  longlong val_int()
  {
    return val_int_from_val_raw(this);
  }
  double val_real()
  {
    return val_real_from_val_raw(this);
  }
  my_decimal *val_decimal(my_decimal *to)
  {
    return val_decimal_from_val_raw(this, to);
  }
  bool get_date(MYSQL_TIME *ltime, ulonglong fuzzydate)
  {
    return get_date_from_val_raw(this, ltime, fuzzydate);
  }

  String *val_raw_native(String *to)
  {
    if (!has_value())
      return 0;
    to->set(m_value, sizeof(m_value), &my_charset_bin);
    return to;
  }

  Field *create_tmp_field(bool group, TABLE *table, uint convert_blob_length)
  {
    /*
      Note, this method is actually not really needed at the moment,
      because Item::create_tmp_field() covers non-traditional types.
      But this will change. See the comment in Item::create_tmp_field()
      in sql_select.cc.
    */
    MEM_ROOT *mem_root= table->in_use->mem_root;
    Field *field= new(mem_root) Field_inet6(name, Record_addr(maybe_null));
    if (field)
      field->init(table);
    return field;
  }

  bool cache_value()
  {
    if (!example)
      return false;
    value_cached= true;
    StringBuffer<64> tmp;
    /**
      TODO: It should be example->val_raw_result_with_conversion()
      instead of example->val_raw() in the code below.
      Implement these methods in Type_handler_inet6_static_definitions:
      - String *val_raw_result_with_conversion(Item *item, String *to);
      - String *val_raw_result_from_val_str_result(Item *item, String *to);
      - String *val_raw_result_from_val_int_result(Item *item, String *to);
      - String *val_raw_result_from_val_real_result(Item *item, String *to);
      - String *val_raw_result_from_val_decimal_result(Item *item, String *to);
      - String *val_raw_result_from_get_date_result(Item *item, String *to);
      It's important for Item_field and Item_ref.
      TODO: add convering tests
    */
    String *str= example->field_type() == Item_cache_inet6::field_type() ?
                 example->val_raw_native_result(&tmp) :
                 example->val_raw(&type_handler_inet6_singleton, &tmp);

    if ((null_value= example->null_value))
    {
      reset_value();
    }
    else
    {
      DBUG_ASSERT(str && str->length() == binary_length());
      memcpy(m_value, str->ptr(), binary_length());
    }
    return true;
  }
  int save_in_field(Field *field, bool no_conversions)
  {
    if (!has_value())
      return set_field_to_null_with_conversions(field, no_conversions);
    if (field->type() ==
        Type_handler_inet6_static_definitions::field_type())
    {
      field->set_notnull();
      int error= field->store_raw_native(m_value, sizeof(m_value));
      return error ? error : field->table->in_use->is_error() ? 1 : 0;
    }
    return Item_cache::save_in_field(field, no_conversions);
  }
};


class Item_typecast_inet6: public Item_func,
                           private Type_handler_inet6_static_definitions
{
public:
  Item_typecast_inet6(THD *thd, Item *a) :Item_func(thd, a) {}

  const Type_handler *type_handler() const
  { return &type_handler_inet6_singleton; }
  enum_field_types field_type() const
  { return Type_handler_inet6_static_definitions::field_type(); }
  Item_result result_type () const
  { return Type_handler_inet6_static_definitions::result_type(); }
  enum Item_result cmp_type () const
  { return Type_handler_inet6_static_definitions::cmp_type(); }
  enum Item_result cast_to_int_type () const
  { return Type_handler_inet6_static_definitions::cast_to_int_type(); }

  bool is_blob_field_type() const { return false; }
  bool is_fixed_length_binary_type() const { return true; }
  Item *make_typecast_item(THD *thd, Item *arg) const
  {
    return new (thd->mem_root) Item_typecast_inet6(thd, arg);
  }

  /*************************************************************/
  enum Functype functype() const { return CHAR_TYPECAST_FUNC; }
  bool eq(const Item *item, bool binary_cmp) const
  {
    if (this == item)
      return true;
    if (item->type() != FUNC_ITEM ||
        functype() != ((Item_func*)item)->functype())
      return false;
    if (field_type() != ((Item_func*) item)->field_type())
      return false;
    Item_typecast_inet6 *cast= (Item_typecast_inet6*) item;
    if (!args[0]->eq(cast->args[0], binary_cmp))
      return false;
    return true;
  }
  const char *func_name() const { return "cast_as_inet6"; }
  void print(String *str, enum_query_type query_type)
  {
    str->append(STRING_WITH_LEN("cast("));
    args[0]->print(str, query_type);
    str->append(STRING_WITH_LEN(" as inet6)"));
  }
  void fix_length_and_dec()
  {
    max_length= Type_handler_inet6_static_definitions::char_length();
    collation.set(DTCollation_inet6());
  }
  String *val_str(String *to)
  {
    return val_str_from_val_raw(this, to);
  }
  longlong val_int()
  {
    return val_int_from_val_raw(this);
  }
  double val_real()
  {
    return val_real_from_val_raw(this);
  }
  my_decimal *val_decimal(my_decimal *to)
  {
    return val_decimal_from_val_raw(this, to);
  }
  bool get_date(MYSQL_TIME *ltime, ulonglong fuzzydate)
  {
    return get_date_from_val_raw(this, ltime, fuzzydate);
  }
  String *val_raw_native(String *to)
  {
    String *res= val_raw_with_optional_conversion(&type_handler_inet6_singleton,
                                                  args[0], to);
    null_value= args[0]->null_value;
    return res;
  }
  // save_in_field() is not needed. Item::save_in_field() is OK.
};


class Arg_comparator_inet6: public Arg_comparator,
                            private Type_handler_inet6_static_definitions
{
  String *arg_val_raw(Item *item, String *to) const
  {
    return val_raw_with_optional_conversion(&type_handler_inet6_singleton,
                                            item, to);
  }

public:

  int compare_inet6()
  {
    String *str1, *str2;
    if (!(str1= arg_val_raw(*a, &value1)) ||
        !(str2= arg_val_raw(*b, &value2)))
      goto null;
    if (set_null)
      owner->null_value= 0;
    return cmp_raw(str1, str2);
  null:
    if (set_null)
      owner->null_value= 1;
    return -1;
  }

  int compare_e_inet6()
  {
    String *str1, *str2;
    bool a_is_null= !(str1= arg_val_raw(*a, &value1));
    bool b_is_null= !(str2= arg_val_raw(*b, &value2));
    if (a_is_null || b_is_null)
      return MY_TEST(a_is_null == b_is_null);
    return MY_TEST(cmp_raw(str1, str2) == 0);
  }

  bool set_cmp_func_inet6()
  {
    set_func(is_owner_equal_func() ?
             (arg_cmp_func) &Arg_comparator_inet6::compare_e_inet6 :
             (arg_cmp_func) &Arg_comparator_inet6::compare_inet6,
             &type_handler_inet6_singleton);
    a= cache_converted_constant(thd, a, &a_cache);
    b= cache_converted_constant(thd, b, &b_cache);
    return false;
  }

  Item** cache_converted_constant(THD *thd_arg, Item **value,
                                  Item **cache_item)
  {
    // Don't need a cache if doing context analysis only.
    if (!thd_arg->lex->is_ps_or_view_context_analysis() &&
        (*value)->const_item() &&
        field_type() != (*value)->field_type())
    {
      Item_cache *cache= type_handler_inet6_singleton.make_cache_item(thd_arg,
                                                                      *value);
      cache->setup(thd_arg, *value);
      *cache_item= cache;
      return cache_item;
    }
    return value;
  }

};


Field *Type_handler_inet6::make_table_field(MEM_ROOT *mem_root,
                        TABLE_SHARE *share,
                        const char *field_name,
                        const Record_addr &rec,
                        const Create_attr &attr) const
{
  return new(mem_root) Field_inet6(field_name, rec);
}


Field *Type_handler_inet6::make_table_field(MEM_ROOT *mem_root,
                        TABLE_SHARE *share,
                        const char *field_name, const Record_addr &rec,
                        const Type_std_attributes &attr,
                        const Type_ext_attributes &eattr,
                        bool set_blob_packlength) const
{
  return new(mem_root) Field_inet6(field_name, rec);
}


Field *
Type_handler_inet6::make_conversion_table_field(TABLE *table, uint metadata,
                                                const Field *target) const
{
  return new(table->in_use->mem_root) Field_inet6("",
                                                  Record_addr(NULL,
                                                              (uchar*)"",
                                                              1));
}


Field *
Type_handler_inet6::make_num_distinct_aggregator_field(MEM_ROOT *mem_root,
                                                       const Item *item)
                                                       const
{
  return Type_handler_newdecimal().
         make_num_distinct_aggregator_field(mem_root, item);
}


Item_cache *
Type_handler_inet6::make_cache_item(THD *thd, const Item *item) const
{
  return new (thd->mem_root) Item_cache_inet6(thd);
}


Item *Type_handler_inet6::make_typecast_item(THD *thd, Item *arg) const
{
  return new (thd->mem_root) Item_typecast_inet6(thd, arg);
}


bool
Type_handler_inet6::set_comparator_func(Arg_comparator *cmp) const
{
  return ((Arg_comparator_inet6*)cmp)->set_cmp_func_inet6();
}


longlong
Type_handler_inet6::Item_func_between_val_int(Item_func_between *func) const
{
  return func->val_int_cmp_raw();
}
