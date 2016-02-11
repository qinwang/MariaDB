#ifndef SQL_TYPE_H_INCLUDED
#define SQL_TYPE_H_INCLUDED
/*
   Copyright (c) 2015  MariaDB Foundation.

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

#ifdef USE_PRAGMA_INTERFACE
#pragma interface			/* gcc class implementation */
#endif

#include "mysqld.h"

class Field;
class Item;
class Item_cache;
class Item_func_hex;
class Item_func_between;
class Item_sum_hybrid;
class Item_type_holder;
class Create_attr;
class Column_definition;
class Type_std_attributes;
class Type_ext_attributes;
class Sort_param;
struct TABLE;
struct SORT_FIELD_ATTR;
class String;
class Item_func_hybrid_field_type;
class Arg_comparator;

class Name: private LEX_CSTRING
{
public:
  Name(const char *str_arg, uint length_arg)
  {
    LEX_CSTRING::str= str_arg;
    LEX_CSTRING::length= length_arg;
  }
  Name()
  {
    LEX_CSTRING::str= NULL;
    LEX_CSTRING::length= 0;
  }
  const char *ptr() const { return LEX_CSTRING::str; }
  uint length() const { return LEX_CSTRING::length; }
  bool eq(const Name &name) const
  {
    if (length() != name.length())
      return false;
    if (!length())
      return true;
    return my_strnncoll(&my_charset_latin1,
                        (const uchar *) ptr(), length(),
                        (const uchar *) name.ptr(), name.length()) == 0;
  }
};


class Record_addr
{
public:
  uchar *ptr;  // Position to field in record
  /**
     Byte where the @c NULL bit is stored inside a record. If this Field is a
     @c NOT @c NULL field, this member is @c NULL.
  */
  uchar *null_ptr;
  uchar null_bit;  // Bit used to test null bit
  Record_addr(uchar *ptr_arg, uchar *null_ptr_arg, uchar null_bit_arg)
    :ptr(ptr_arg), null_ptr(null_ptr_arg), null_bit(null_bit_arg)
  { }
  Record_addr(bool maybe_null)
    :ptr(NULL), null_ptr(maybe_null ? (uchar *) "" : NULL), null_bit(0)
  { }
  bool eq(const Record_addr *other)
  {
    return (ptr == other->ptr && null_ptr == other->null_ptr &&
            null_bit == other->null_bit);
  }
};


class Type_handler
{
protected:
  uint pack_flags_string(CHARSET_INFO *cs) const;
  uint pack_flags_numeric(uint flags, uint decimals) const;
  const Type_handler *string_type_handler(uint max_octet_length) const;
  void make_sort_key_longlong(uchar *to,
                              bool maybe_null, bool null_value,
                              bool unsigned_flag,
                              longlong value) const;
  void error_cant_merge_types(const char *op, const Type_handler *h1,
                                              const Type_handler *h2) const;
public:
  enum_field_types
  field_type_for_temporal_comparison(const Type_handler *other) const;

  static const Type_handler *get_handler_by_field_type(enum_field_types type);
  static const Type_handler *get_handler_by_real_type(enum_field_types type);
  /**
    Check if a data type is a traditional type, known as of version 10.1.
    Note, some traditional type can become dynamically loadable (e.g. GEOMETRY).
  */
  static bool is_traditional_type(enum_field_types type)
  {
    return type <= MYSQL_TYPE_TIME2 || type >= MYSQL_TYPE_NEWDECIMAL;
  }
  virtual const Name type_name() const= 0;
  virtual enum_field_types field_type() const= 0;
  virtual enum_field_types real_field_type() const { return field_type(); }
  virtual Item_result result_type() const= 0;
  virtual Item_result cmp_type() const= 0;
  // Requires the engine not to have HA_NO_BLOBS
  virtual bool is_blob_field_type() const= 0;
  virtual const Type_handler*
  type_handler_adjusted_to_max_octet_length(uint max_octet_length,
                                            CHARSET_INFO *cs) const
  { return this; }
  virtual ~Type_handler() {}
  virtual bool check_column_definition(THD *thd, Column_definition *def) const;
  virtual bool prepare_column_definition(Column_definition *def,
                                         longlong table_flags) const= 0;
  virtual Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                                  const char *name, const Record_addr &addr,
                                  const Create_attr &attr) const= 0;
  virtual Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                                  const char *name, const Record_addr &addr,
                                  const Type_std_attributes &attr,
                                  const Type_ext_attributes &eattr,
                                  bool set_blob_packlength) const= 0;
  /**
    Makes a temporary table Field to handle numeric aggregate functions,
    e.g. SUM(DISTINCT expr), AVG(DISTINCT expr), etc.
  */
  virtual Field *make_num_distinct_aggregator_field(MEM_ROOT *,
                                                    const Item *) const;
  /**
    Makes a temporary table Field to handle RBR replication type conversion.
    @param TABLE    - The conversion table the field is going to be added to.
                      It's used to access to table->in_use->mem_root,
                      to create the new field on the table memory root,
                      as well as to increment statistics in table->share
                      (e.g. table->s->blob_count).
    @param metadata - Metadata from the binary log.
    @param target   - The field in the target table on the slave.

    Note, the data types of "target" and of "this" are not necessarily
    always the same, in general case it's possible that:
            this->field_type() != target->field_type()
    and/or
            this->real_type( ) != target->real_type()

    This method decodes metadata according to this->real_type()
    and creates a new field also according to this->real_type().

    In some cases it lurks into "target", to get some extra information, e.g.:
    - unsigned_flag for numeric fields
    - charset() for string fields
    - typelib and field_length for SET and ENUM
    - geom_type and srid for GEOMETRY
    This information is not available in the binary log, so
    we assume that these fields are the same on the master and on the slave.
  */
  virtual Field *make_conversion_table_field(TABLE *TABLE,
                                             uint metadata,
                                             const Field *target) const= 0;
  virtual int Item_save_in_field(Item *item, Field *field,
                                 bool no_conversions) const= 0;
  virtual Item_cache *make_cache_item(THD *thd, const Item *item) const= 0;
  virtual void make_sort_key(uchar *to, Item *item,
                             const SORT_FIELD_ATTR *sort_field,
                             Sort_param *param) const= 0;
  virtual void sortlength(THD *thd,
                          const Type_std_attributes *item,
                          SORT_FIELD_ATTR *attr) const= 0;
  virtual uint32 calc_pack_length(uint32 length) const= 0;
  virtual uint32 calc_display_length(const Type_std_attributes *attr) const= 0;

  virtual bool Item_type_holder_join_attributes(THD *thd,
                                                Item_type_holder *holder,
                                                Item *item) const= 0;
  // HEX routines
  virtual
  String *Item_func_hex_val_str_ascii(Item_func_hex *item,
                                      String *str) const= 0;
  // Hybrid function routines;
  virtual
  String *Item_func_hybrid_field_type_val_str(Item_func_hybrid_field_type *item,
                                              String *str) const= 0;
  virtual longlong
  Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item)
                                       const= 0;

  virtual double
  Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item)
                                       const= 0;
  virtual my_decimal*
  Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                          my_decimal *to) const= 0;
  virtual bool
  Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                       MYSQL_TIME *ltime, ulonglong fuzzydate)
                                       const= 0;

  // Hybrid comparison routines
  virtual bool
  Item_func_between_fix_length_and_dec(Item_func_between *func) const= 0;
  virtual longlong
  Item_func_between_val_int(Item_func_between *func) const= 0;

  virtual bool set_comparator_func(Arg_comparator *cmp) const= 0;

  // Hybrid aggregate routines
  virtual bool
  Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const= 0;
};


class Type_handler_numeric: public Type_handler
{
protected:
  bool Item_sum_hybrid_fix_length_and_dec_numeric(Item_sum_hybrid *func,
                                                  const Type_handler *handler)
                                                  const;
public:
  bool is_blob_field_type() const { return false; }
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
};


/*** Abstract classes for every XXX_RESULT */

class Type_handler_real_result: public Type_handler_numeric
{
public:
  Item_result result_type() const { return REAL_RESULT; }
  Item_result cmp_type() const { return REAL_RESULT; }
  virtual ~Type_handler_real_result() {}
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
  Item_cache *make_cache_item(THD *thd, const Item *item) const;
  void make_sort_key(uchar *to, Item *item, const SORT_FIELD_ATTR *sort_field,
                     Sort_param *param) const;
  void sortlength(THD *thd,
                  const Type_std_attributes *item,
                  SORT_FIELD_ATTR *attr) const;
  String *Item_func_hex_val_str_ascii(Item_func_hex *item, String *str) const;
  String *
  Item_func_hybrid_field_type_val_str(Item_func_hybrid_field_type *item,
                                      String *str) const;
  longlong
  Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const;
  double
  Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const;
  my_decimal*
  Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                          my_decimal *to) const;
  bool
  Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                       MYSQL_TIME *ltime,
                                       ulonglong fuzzydate) const;
  bool Item_func_between_fix_length_and_dec(Item_func_between *func) const;
  longlong Item_func_between_val_int(Item_func_between *func) const;
  bool set_comparator_func(Arg_comparator *cmp) const;
  bool Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const;
};


class Type_handler_decimal_result: public Type_handler_numeric
{
public:
  Item_result result_type() const { return DECIMAL_RESULT; }
  Item_result cmp_type() const { return DECIMAL_RESULT; }
  virtual ~Type_handler_decimal_result() {};
  uint32 calc_display_length(const Type_std_attributes *attr) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
  Field *make_num_distinct_aggregator_field(MEM_ROOT *, const Item *) const;
  Item_cache *make_cache_item(THD *thd, const Item *item) const;
  void make_sort_key(uchar *to, Item *item, const SORT_FIELD_ATTR *sort_field,
                     Sort_param *param) const;
  void sortlength(THD *thd,
                  const Type_std_attributes *item,
                  SORT_FIELD_ATTR *attr) const;
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const;
  String *Item_func_hex_val_str_ascii(Item_func_hex *item, String *str) const;
  String *
  Item_func_hybrid_field_type_val_str(Item_func_hybrid_field_type *item,
                                      String *str) const;
  longlong
  Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const;
  double
  Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const;
  my_decimal*
  Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                          my_decimal *to) const;
  bool
  Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                       MYSQL_TIME *ltime,
                                       ulonglong fuzzydate) const;
  bool Item_func_between_fix_length_and_dec(Item_func_between *func) const;
  longlong Item_func_between_val_int(Item_func_between *func) const;
  bool set_comparator_func(Arg_comparator *cmp) const;
  bool Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const;
};


class Type_handler_int_result: public Type_handler_numeric
{
public:
  Item_result result_type() const { return INT_RESULT; }
  Item_result cmp_type() const { return INT_RESULT; }
  virtual ~Type_handler_int_result() {}
  Field *make_num_distinct_aggregator_field(MEM_ROOT *, const Item *) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
  Item_cache *make_cache_item(THD *thd, const Item *item) const;
  void make_sort_key(uchar *to, Item *item, const SORT_FIELD_ATTR *sort_field,
                     Sort_param *param) const;
  void sortlength(THD *thd,
                  const Type_std_attributes *item,
                  SORT_FIELD_ATTR *attr) const;
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const;
  String *Item_func_hex_val_str_ascii(Item_func_hex *item, String *str) const;
  String *
  Item_func_hybrid_field_type_val_str(Item_func_hybrid_field_type *item,
                                      String *str) const;
  longlong
  Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const;
  double
  Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const;
  my_decimal*
  Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                          my_decimal *to) const;
  bool
  Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                       MYSQL_TIME *ltime,
                                       ulonglong fuzzydate) const;
  bool Item_func_between_fix_length_and_dec(Item_func_between *func) const;
  longlong Item_func_between_val_int(Item_func_between *func) const;
  bool set_comparator_func(Arg_comparator *cmp) const;
  bool Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const;
};


class Type_handler_temporal_result: public Type_handler
{
public:
  Item_result result_type() const { return STRING_RESULT; }
  Item_result cmp_type() const { return TIME_RESULT; }
  bool is_blob_field_type() const { return false; }
  virtual ~Type_handler_temporal_result() {}
  Item_cache *make_cache_item(THD *thd, const Item *item) const;
  uint32 calc_display_length(const Type_std_attributes *attr) const;
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  void make_sort_key(uchar *to, Item *item,  const SORT_FIELD_ATTR *sort_field,
                     Sort_param *param) const;
  void sortlength(THD *thd,
                  const Type_std_attributes *item,
                  SORT_FIELD_ATTR *attr) const;
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const;
  String *Item_func_hex_val_str_ascii(Item_func_hex *item, String *str) const;
  String *
  Item_func_hybrid_field_type_val_str(Item_func_hybrid_field_type *item,
                                      String *str) const;
  longlong
  Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const;
  double
  Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const;
  my_decimal*
  Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                          my_decimal *to) const;
  bool
  Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                       MYSQL_TIME *ltime,
                                       ulonglong fuzzydate) const;
  bool Item_func_between_fix_length_and_dec(Item_func_between *func) const;
  longlong Item_func_between_val_int(Item_func_between *func) const;
  bool set_comparator_func(Arg_comparator *cmp) const;
  bool Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const;
};


class Type_handler_string_result: public Type_handler
{
public:
  Item_result result_type() const { return STRING_RESULT; }
  Item_result cmp_type() const { return STRING_RESULT; }
  uint32 calc_display_length(const Type_std_attributes *attr) const;
  bool is_blob_field_type() const { return false; }
  virtual ~Type_handler_string_result() {}
  const Type_handler *
  type_handler_adjusted_to_max_octet_length(uint max_octet_length,
                                            CHARSET_INFO *cs) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const
  {
    /*
      All string fields are handled in a separate branch
      in field.cc:make_field().
    */
    DBUG_ASSERT(0);
    return NULL;
  }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                                  const char *name, const Record_addr &addr,
                                  const Type_std_attributes &attr,
                                  const Type_ext_attributes &eattr,
                                  bool set_blob_packlength) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
  Item_cache *make_cache_item(THD *thd, const Item *item) const;
  void make_sort_key(uchar *to, Item *item, const SORT_FIELD_ATTR *sort_field,
                     Sort_param *param) const;
  void sortlength(THD *thd,
                  const Type_std_attributes *item,
                  SORT_FIELD_ATTR *attr) const;
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const;
  String *Item_func_hex_val_str_ascii(Item_func_hex *item, String *str) const;
  String *
  Item_func_hybrid_field_type_val_str(Item_func_hybrid_field_type *item,
                                      String *str) const;
  longlong
  Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const;
  double
  Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const;
  my_decimal*
  Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                          my_decimal *to) const;
  bool
  Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                       MYSQL_TIME *ltime,
                                       ulonglong fuzzydate) const;
  bool Item_func_between_fix_length_and_dec(Item_func_between *func) const;
  longlong Item_func_between_val_int(Item_func_between *func) const;
  bool set_comparator_func(Arg_comparator *cmp) const;
  bool Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const;
};


/***
  Instantiable classes for every MYSQL_TYPE_XXX

  There are no Type_handler_xxx for the following types:
  - MYSQL_TYPE_VAR_STRING (old VARCHAR) - mapped to MYSQL_TYPE_VARSTRING
  - MYSQL_TYPE_ENUM                     - mapped to MYSQL_TYPE_VARSTRING
  - MYSQL_TYPE_SET:                     - mapped to MYSQL_TYPE_VARSTRING

  because the functionality that currently uses Type_handler
  (e.g. hybrid type functions) does not need to distinguish between
  these types and VARCHAR.
  For example:
    CREATE TABLE t2 AS SELECT COALESCE(enum_column) FROM t1;
  creates a VARCHAR column.

  There most likely be Type_handler_enum and Type_handler_set later,
  when the Type_handler infrastructure gets used in more pieces of the code.
*/


class Type_handler_tiny: public Type_handler_int_result
{
public:
  virtual ~Type_handler_tiny() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("tinyint")); }
  enum_field_types field_type() const { return MYSQL_TYPE_TINY; }
  uint32 calc_pack_length(uint32 length) const { return 1; }
  uint32 calc_display_length(const Type_std_attributes *attr) const
  { return 4; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *TABLE, uint metadata,
                                     const Field *target) const;
};


class Type_handler_short: public Type_handler_int_result
{
public:
  virtual ~Type_handler_short() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("smallint")); }
  enum_field_types field_type() const { return MYSQL_TYPE_SHORT; }
  uint32 calc_pack_length(uint32 length) const { return 2; }
  uint32 calc_display_length(const Type_std_attributes *attr) const
  { return 6; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *TABLE, uint metadata,
                                     const Field *target) const;
};


class Type_handler_long: public Type_handler_int_result
{
public:
  virtual ~Type_handler_long() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("int")); }
  enum_field_types field_type() const { return MYSQL_TYPE_LONG; }
  uint32 calc_pack_length(uint32 length) const { return 4; }
  uint32 calc_display_length(const Type_std_attributes *attr) const
  { return MY_INT32_NUM_DECIMAL_DIGITS; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *TABLE, uint metadata,
                                     const Field *target) const;
};


class Type_handler_longlong: public Type_handler_int_result
{
public:
  virtual ~Type_handler_longlong() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("bigint")); }
  enum_field_types field_type() const { return MYSQL_TYPE_LONGLONG; }
  uint32 calc_pack_length(uint32 length) const { return 8; }
  uint32 calc_display_length(const Type_std_attributes *attr) const
  { return 20; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *TABLE, uint metadata,
                                     const Field *target) const;
};


class Type_handler_int24: public Type_handler_int_result
{
public:
  virtual ~Type_handler_int24() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("mediumint")); }
  enum_field_types field_type() const { return MYSQL_TYPE_INT24; }
  uint32 calc_pack_length(uint32 length) const { return 3; }
  uint32 calc_display_length(const Type_std_attributes *attr) const
  { return 8; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_year: public Type_handler_int_result
{
public:
  virtual ~Type_handler_year() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("year")); }
  enum_field_types field_type() const { return MYSQL_TYPE_YEAR; }
  uint32 calc_pack_length(uint32 length) const { return 1; }
  uint32 calc_display_length(const Type_std_attributes *attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_bit: public Type_handler_int_result
{
public:
  virtual ~Type_handler_bit() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("bit")); }
  enum_field_types field_type() const { return MYSQL_TYPE_BIT; }
  uint32 calc_pack_length(uint32 length) const { return length / 8; }
  uint32 calc_display_length(const Type_std_attributes *attr) const;
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const
  {
    /*
      We have sql_field->pack_flag already set here, see
      mysql_prepare_create_table().
    */
    return false;
  }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const
  {
    DBUG_ASSERT(0); // Handled separately in field.cc:make_field().
    return NULL;
  }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_float: public Type_handler_real_result
{
public:
  virtual ~Type_handler_float() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("float")); }
  enum_field_types field_type() const { return MYSQL_TYPE_FLOAT; }
  uint32 calc_pack_length(uint32 length) const { return sizeof(float); }
  uint32 calc_display_length(const Type_std_attributes *attr) const
  { return 25; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_num_distinct_aggregator_field(MEM_ROOT *, const Item *) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const;
};


class Type_handler_double: public Type_handler_real_result
{
public:
  virtual ~Type_handler_double() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("double")); }
  enum_field_types field_type() const { return MYSQL_TYPE_DOUBLE; }
  uint32 calc_pack_length(uint32 length) const { return sizeof(double); }
  uint32 calc_display_length(const Type_std_attributes *attr) const
  { return 53; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const;
};


class Type_handler_time: public Type_handler_temporal_result
{
public:
  virtual ~Type_handler_time() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("time")); }
  enum_field_types field_type() const { return MYSQL_TYPE_TIME; }
  uint32 calc_pack_length(uint32 length) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
};


class Type_handler_time2: public Type_handler_temporal_result
{
public:
  virtual ~Type_handler_time2() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("time")); }
  enum_field_types field_type() const { return MYSQL_TYPE_TIME; }
  enum_field_types real_field_type() const { return MYSQL_TYPE_TIME2; }
  uint32 calc_pack_length(uint32 length) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
};


class Type_handler_date: public Type_handler_temporal_result
{
public:
  virtual ~Type_handler_date() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("date")); }
  enum_field_types field_type() const { return MYSQL_TYPE_DATE; }
  uint32 calc_pack_length(uint32 length) const { return 4; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
};


class Type_handler_newdate: public Type_handler_temporal_result
{
public:
  virtual ~Type_handler_newdate() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("date")); }
  enum_field_types field_type() const { return MYSQL_TYPE_DATE; }
  enum_field_types real_field_type() const { return MYSQL_TYPE_NEWDATE; }
  uint32 calc_pack_length(uint32 length) const { return 3; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
};


class Type_handler_datetime: public Type_handler_temporal_result
{
public:
  virtual ~Type_handler_datetime() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("datetime")); }
  enum_field_types field_type() const { return MYSQL_TYPE_DATETIME; }
  uint32 calc_pack_length(uint32 length) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
};


class Type_handler_datetime2: public Type_handler_temporal_result
{
public:
  virtual ~Type_handler_datetime2() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("datetime")); }
  enum_field_types field_type() const { return MYSQL_TYPE_DATETIME; }
  enum_field_types real_field_type() const { return MYSQL_TYPE_DATETIME2; }
  uint32 calc_pack_length(uint32 length) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
};


class Type_handler_timestamp: public Type_handler_temporal_result
{
public:
  virtual ~Type_handler_timestamp() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("timestamp")); }
  enum_field_types field_type() const { return MYSQL_TYPE_TIMESTAMP; }
  uint32 calc_pack_length(uint32 length) const;
  bool prepare_column_definition(Column_definition *def,
                                         longlong table_flags) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
};


class Type_handler_timestamp2: public Type_handler_temporal_result
{
public:
  virtual ~Type_handler_timestamp2() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("timestamp")); }
  enum_field_types field_type() const { return MYSQL_TYPE_TIMESTAMP; }
  enum_field_types real_field_type() const { return MYSQL_TYPE_TIMESTAMP2; }
  uint32 calc_pack_length(uint32 length) const;
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const;
};


class Type_handler_olddecimal: public Type_handler_decimal_result
{
public:
  virtual ~Type_handler_olddecimal() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("decimal")); }
  enum_field_types field_type() const { return MYSQL_TYPE_DECIMAL; }
  uint32 calc_pack_length(uint32 length) const { return length; }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_newdecimal: public Type_handler_decimal_result
{
public:
  virtual ~Type_handler_newdecimal() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("decimal")); }
  enum_field_types field_type() const { return MYSQL_TYPE_NEWDECIMAL; }
  uint32 calc_pack_length(uint32 length) const;
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_null: public Type_handler_string_result
{
public:
  virtual ~Type_handler_null() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("null")); }
  enum_field_types field_type() const { return MYSQL_TYPE_NULL; }
  uint32 calc_pack_length(uint32 length) const { return 0; }
  uint32 calc_display_length(const Type_std_attributes *attr) const
  { return 0; }
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_string: public Type_handler_string_result
{
public:
  virtual ~Type_handler_string() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("char")); }
  enum_field_types field_type() const { return MYSQL_TYPE_STRING; }
  uint32 calc_pack_length(uint32 length) const { return length; }
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_varchar: public Type_handler_string_result
{
public:
  virtual ~Type_handler_varchar() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("varchar")); }
  enum_field_types field_type() const { return MYSQL_TYPE_VARCHAR; }
  uint32 calc_pack_length(uint32 length) const
  {
    return (length + (length < 256 ? 1: 2));
  }
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_blob: public Type_handler_string_result
{
public:
  bool is_blob_field_type() const { return true; }
  virtual ~Type_handler_blob() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("blob")); }
  enum_field_types field_type() const { return MYSQL_TYPE_BLOB; }
  uint32 calc_pack_length(uint32 length) const;
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const
  {
    return Type_handler_string_result::make_table_field(root, share, name,
                                                        addr, attr);
  }
  Field *make_table_field(MEM_ROOT *mem_root, TABLE_SHARE *share,
                          const char *name, const Record_addr &rec,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_tiny_blob: public Type_handler_blob
{
public:
  virtual ~Type_handler_tiny_blob() {}
  enum_field_types field_type() const { return MYSQL_TYPE_TINY_BLOB; }
  uint32 calc_pack_length(uint32 length) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_medium_blob: public Type_handler_blob
{
public:
  virtual ~Type_handler_medium_blob() {}
  enum_field_types field_type() const { return MYSQL_TYPE_MEDIUM_BLOB; }
  uint32 calc_pack_length(uint32 length) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


class Type_handler_long_blob: public Type_handler_blob
{
public:
  virtual ~Type_handler_long_blob() {}
  enum_field_types field_type() const { return MYSQL_TYPE_LONG_BLOB; }
  uint32 calc_pack_length(uint32 length) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
};


#ifdef HAVE_SPATIAL
class Type_handler_geometry: public Type_handler_blob
{
public:
  virtual ~Type_handler_geometry() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("geometry")); }
  enum_field_types field_type() const { return MYSQL_TYPE_GEOMETRY; }
  uint32 calc_pack_length(uint32 length) const;
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const
  {
    /*
      All string fields are handled in a separate branch
      in field.cc:make_field().
    */
    DBUG_ASSERT(0);
    return NULL;
  }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                                  const char *name, const Record_addr &addr,
                                  const Type_std_attributes &attr,
                                  const Type_ext_attributes &eattr,
                                  bool set_blob_packlength) const;
};
#endif


class Type_handler_enum: public Type_handler_string_result
{
public:
  virtual ~Type_handler_enum() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("enum")); }
  enum_field_types field_type() const { return MYSQL_TYPE_VARCHAR; }
  virtual enum_field_types real_field_type() const { return MYSQL_TYPE_ENUM; }
  uint32 calc_pack_length(uint32 length) const;
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const
  {
    // This will do DBUG_ASSERT(0)
    return Type_handler_string_result::make_table_field(root, share,
                                                        name, addr, attr);
  }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const;
};


class Type_handler_set: public Type_handler_string_result
{
public:
  virtual ~Type_handler_set() {}
  const Name type_name() const { return Name(C_STRING_WITH_LEN("set")); }
  enum_field_types field_type() const { return MYSQL_TYPE_VARCHAR; }
  uint32 calc_pack_length(uint32 length) const;
  virtual enum_field_types real_field_type() const { return MYSQL_TYPE_SET; }
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const;
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const
  {
    // This will do DBUG_ASSERT(0)
    return Type_handler_string_result::make_table_field(root, share,
                                                        name, addr, attr);
  }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const;
  Field *make_conversion_table_field(TABLE *, uint metadata,
                                     const Field *target) const;
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const;
};


/**
  A handler for hybrid type functions, e.g.
  COALESCE(), IF(), IFNULL(), NULLIF(), CASE,
  numeric operators,
  UNIX_TIMESTAMP(), TIME_TO_SEC().

  Makes sure that field_type(), cmp_type() and result_type()
  are always in sync to each other for hybrid functions.
*/
class Type_handler_hybrid_field_type: public Type_handler
{
  const Type_handler *m_type_handler;
  const Type_handler *get_handler_by_result_type(Item_result type) const;
protected:
  bool merge_non_traditional_types(const char *op, const Type_handler *other,
                                   uint *non_traditional_count);
  bool merge_type(const char *op, const Type_handler *other,
                  bool treat_bit_as_number);
  void finalize_type(uint unsigned_count, uint total_count);
  bool agg_field_type(const char *op, Item **items, uint nitems,
                      bool treat_bit_as_number);
public:
  Type_handler_hybrid_field_type();
  Type_handler_hybrid_field_type(const Type_handler *handler)
   :m_type_handler(handler)
  { }
  Type_handler_hybrid_field_type(enum_field_types type)
    :m_type_handler(get_handler_by_field_type(type))
  { }
  Type_handler_hybrid_field_type(const Type_handler_hybrid_field_type *other)
    :m_type_handler(other->m_type_handler)
  { }

  bool merge_type_for_comparison(const char *op, const Type_handler *other);

  const Type_handler *type_handler() const { return m_type_handler; }
  const Name type_name() const { return m_type_handler->type_name(); }
  enum_field_types field_type() const { return m_type_handler->field_type(); }
  enum_field_types real_field_type() const
  {
    return m_type_handler->real_field_type();
  }
  Item_result result_type() const { return m_type_handler->result_type(); }
  Item_result cmp_type() const { return m_type_handler->cmp_type(); }
  int Item_save_in_field(Item *item, Field *field, bool no_conversions) const
  {
    return m_type_handler->Item_save_in_field(item, field, no_conversions);
  }
  bool is_blob_field_type() const
  { return m_type_handler->is_blob_field_type(); }
  void set_handler(const Type_handler *other)
  {
    /*
      Safety: make sure we have an address of a singeton handler objects here,
      e.g. one of those permanently instantiated in sql_type.cc.
      Caching a pointer to just any temporary variable derived from
      Type_handler (e.g. an address of some Item) is potentially dangerous,
      as the temporary variable may disappear when "this" is used.
    */
    DBUG_ASSERT(other == get_handler_by_real_type(other->real_field_type()));
    m_type_handler= other;
  }
  const Type_handler *set_handler_by_result_type(Item_result type)
  {
    return (m_type_handler= get_handler_by_result_type(type));
  }
  const Type_handler *set_handler_by_result_type(Item_result type,
                                                 uint max_octet_length,
                                                 CHARSET_INFO *cs)
  {
    m_type_handler= get_handler_by_result_type(type);
    return m_type_handler=
      m_type_handler->type_handler_adjusted_to_max_octet_length(max_octet_length,
                                                                cs);
  }
  const Type_handler *set_handler_by_field_type(enum_field_types type)
  {
    return (m_type_handler= get_handler_by_field_type(type));
  }
  const Type_handler *set_handler_by_real_type(enum_field_types type)
  {
    return (m_type_handler= get_handler_by_real_type(type));
  }
  const Type_handler *
  type_handler_adjusted_to_max_octet_length(uint max_octet_length,
                                            CHARSET_INFO *cs) const
  {
    return
      m_type_handler->type_handler_adjusted_to_max_octet_length(max_octet_length,
                                                                cs);
  }
  bool prepare_column_definition(Column_definition *def,
                                 longlong table_flags) const
  {
    return m_type_handler->prepare_column_definition(def, table_flags);
  }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Create_attr &attr) const
  {
    return m_type_handler->make_table_field(root, share, name, addr, attr);
  }
  Field *make_table_field(MEM_ROOT *root, TABLE_SHARE *share,
                          const char *name, const Record_addr &addr,
                          const Type_std_attributes &attr,
                          const Type_ext_attributes &eattr,
                          bool set_blob_packlength) const
  {
    return m_type_handler->make_table_field(root, share, name, addr,
                                            attr, eattr,
                                            set_blob_packlength);
  }
  Field *make_num_distinct_aggregator_field(MEM_ROOT *mem_root,
                                            const Item *item) const
  {
    return m_type_handler->make_num_distinct_aggregator_field(mem_root, item);
  }
  Field *make_conversion_table_field(TABLE *table, uint metadata,
                                     const Field *target) const
  {
    return m_type_handler->make_conversion_table_field(table, metadata, target);
  }
  Item_cache *make_cache_item(THD *thd, const Item *item) const
  {
    return m_type_handler->make_cache_item(thd, item);
  }
  void make_sort_key(uchar *to, Item *item, const SORT_FIELD_ATTR *sort_field,
                     Sort_param *param) const
  {
    m_type_handler->make_sort_key(to, item, sort_field, param);
  }
  void sortlength(THD *thd,
                  const Type_std_attributes *item,
                  SORT_FIELD_ATTR *attr) const
  {
    m_type_handler->sortlength(thd, item, attr);
  }
  uint32 calc_pack_length(uint32 length) const
  {
    return m_type_handler->calc_pack_length(length);
  }
  uint32 calc_display_length(const Type_std_attributes *attr) const
  {
    return m_type_handler->calc_display_length(attr);
  }
  bool Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const
  {
    return m_type_handler->Item_type_holder_join_attributes(thd, holder, item);
  }
  String *Item_func_hex_val_str_ascii(Item_func_hex *item, String *str) const
  {
    return m_type_handler->Item_func_hex_val_str_ascii(item, str);
  }
  String *
  Item_func_hybrid_field_type_val_str(Item_func_hybrid_field_type *item,
                                      String *str) const
  {
    return m_type_handler->Item_func_hybrid_field_type_val_str(item, str);
  }
  longlong
  Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const
  {
    return m_type_handler->Item_func_hybrid_field_type_val_int(item);
  }
  double
  Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const
  {
    return m_type_handler->Item_func_hybrid_field_type_val_real(item);
  }
  my_decimal*
  Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                          my_decimal *to) const
  {
    return m_type_handler->Item_func_hybrid_field_type_val_decimal(item, to);
  }
  bool
  Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                       MYSQL_TIME *ltime, ulonglong fuzzydate)
                                       const
  {
    return m_type_handler->Item_func_hybrid_field_type_get_date(item, ltime,
                                                                fuzzydate);
  }
  bool Item_func_between_fix_length_and_dec(Item_func_between *func) const
  {
    return m_type_handler->Item_func_between_fix_length_and_dec(func);
  }
  longlong Item_func_between_val_int(Item_func_between *func) const
  {
    return m_type_handler->Item_func_between_val_int(func);
  }
  bool set_comparator_func(Arg_comparator *cmp) const
  {
    return m_type_handler->set_comparator_func(cmp);
  }
  bool Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const
  {
    return m_type_handler->Item_sum_hybrid_fix_length_and_dec(func);
  }
};


/**
  This class is used for Item_type_holder, which preserves real_type.
*/
class Type_handler_hybrid_real_field_type:
  public Type_handler_hybrid_field_type
{
public:
  Type_handler_hybrid_real_field_type(const Type_handler *handler)
    :Type_handler_hybrid_field_type(handler)
  { }
  Type_handler_hybrid_real_field_type(enum_field_types type)
    :Type_handler_hybrid_field_type(get_handler_by_real_type(type))
  { }
  const Type_handler *type_handler() const
  { return get_handler_by_field_type(Type_handler_hybrid_field_type::type_handler()->field_type()); }
  const Type_handler *real_type_handler() const
  { return Type_handler_hybrid_field_type::type_handler(); }
};


class Type_handler_register
{
  class Entry
  {
    Name m_name;
    const Type_handler *m_handler;
  public:
    Entry()
      :m_name(), m_handler(NULL)
    { }
    Entry(const Name &name, const Type_handler *handler)
      :m_name(name), m_handler(handler)
    { }
    const Name &name() const { return m_name; }
    const Type_handler *handler() const { return m_handler; }
    void set(const Type_handler *handler)
    {
      m_handler= handler;
    }
  };
  Entry m_handlers[256];
  uint m_min_type;
  uint m_max_type;
public:
  Type_handler_register();
  const Type_handler *handler(enum_field_types type) const
  {
    return m_handlers[type].handler();
  }
  bool add(const Type_handler *handler)
  {
    enum_field_types real_type= handler->real_field_type();
    if (m_handlers[real_type].handler())
    {
      DBUG_ASSERT(0);
      return true;
    }
    set_if_smaller(m_min_type, real_type);
    set_if_bigger(m_max_type, real_type);
    m_handlers[real_type].set(handler);
    return false;
  }
};
extern Type_handler_register Type_handlers;


#endif /* SQL_TYPE_H_INCLUDED */
