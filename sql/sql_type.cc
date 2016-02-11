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

#include "sql_type.h"
#include "sql_const.h"
#include "sql_class.h"
#include "item.h"
#include "log.h"
#include "strfunc.h" // find_type2, find_set

static Type_handler_tiny        type_handler_tiny;
static Type_handler_short       type_handler_short;
static Type_handler_long        type_handler_long;
static Type_handler_longlong    type_handler_longlong;
static Type_handler_int24       type_handler_int24;
static Type_handler_year        type_handler_year;
static Type_handler_bit         type_handler_bit;
static Type_handler_float       type_handler_float;
static Type_handler_double      type_handler_double;
static Type_handler_time        type_handler_time;
static Type_handler_time2       type_handler_time2;
static Type_handler_date        type_handler_date;
static Type_handler_newdate     type_handler_newdate;
static Type_handler_datetime    type_handler_datetime;
static Type_handler_datetime2   type_handler_datetime2;
static Type_handler_timestamp   type_handler_timestamp;
static Type_handler_timestamp2  type_handler_timestamp2;
static Type_handler_olddecimal  type_handler_olddecimal;
static Type_handler_newdecimal  type_handler_newdecimal;
static Type_handler_null        type_handler_null;
static Type_handler_string      type_handler_string;
static Type_handler_varchar     type_handler_varchar;
static Type_handler_tiny_blob   type_handler_tiny_blob;
static Type_handler_medium_blob type_handler_medium_blob;
static Type_handler_long_blob   type_handler_long_blob;
static Type_handler_blob        type_handler_blob;
#ifdef HAVE_SPATIAL
static Type_handler_geometry    type_handler_geometry;
#endif
static Type_handler_enum        type_handler_enum;
static Type_handler_set         type_handler_set;


enum_field_types Type_handler::
  field_type_for_temporal_comparison(const Type_handler *other) const
{
  if (cmp_type() == TIME_RESULT)
  {
    if (other->cmp_type() == TIME_RESULT)
      return Field::field_type_merge(field_type(), other->field_type());
    else
      return field_type();
  }
  else
  {
    if (other->cmp_type() == TIME_RESULT)
      return other->field_type();
    DBUG_ASSERT(0); // Two non-temporal data types, we should not get to here
    return MYSQL_TYPE_DATETIME;
  }
}


void
Type_handler::error_cant_merge_types(const char *op,
                                     const Type_handler *h1,
                                     const Type_handler *h2) const
{
  my_printf_error(ER_UNKNOWN_ERROR,
                  "Illegal data types %s and %s for operation '%s'", MYF(0),
                  h1->type_name().ptr(), h2->type_name().ptr(), op);
}


bool Type_handler_hybrid_field_type::
       merge_non_traditional_types(const char *op, const Type_handler *other,
                                   uint *non_traditional_count)
{
  bool ext1= !Type_handler::is_traditional_type(real_field_type());
  bool ext2= !Type_handler::is_traditional_type(other->real_field_type());
  if ((non_traditional_count[0]= ext1 + ext2) == 2 &&
      type_handler() != other)
  {
    error_cant_merge_types(op, type_handler(), other);
    return true;  // Two different non-traditional types
  }
  if (ext1)
    return false; // The current type won
  if (ext2)
  {
    set_handler(other);
    return false; // The "other" type won
  }
  return false;   // No non-traditional types were found
}


bool Type_handler_hybrid_field_type::
       merge_type_for_comparison(const char *op, const Type_handler *other)
{
  uint non_traditional_count;
  if (merge_non_traditional_types(op, other, &non_traditional_count))
    return true;
  if (non_traditional_count > 0)
    return false;
  switch (item_cmp_type(cmp_type(), other->cmp_type())) {
  case STRING_RESULT:  set_handler(&type_handler_string);     break;
  case INT_RESULT:     set_handler(&type_handler_longlong);   break;
  case REAL_RESULT:    set_handler(&type_handler_double);     break;
  case DECIMAL_RESULT: set_handler(&type_handler_newdecimal); break;
  case TIME_RESULT:
  {
    set_handler_by_field_type(field_type_for_temporal_comparison(other));
    break;
  }
  case ROW_RESULT:
    set_handler(&type_handler_string);
    DBUG_ASSERT(0);
    break;
  }
  return false;
}


/**
  This method is used by:
  - Item_user_var_as_out_param::field_type()
  - Item_func_udf_str::field_type()
  - Item_empty_string::make_field()

  TODO: type_handler_adjusted_to_max_octet_length() and string_type_handler()
  provide very similar functionality, to properly choose between
  VARCHAR/VARBINARY vs TEXT/BLOB variations taking into accoung maximum
  possible octet length.

  We should probably get rid of either of them and use the same method
  all around the code.
*/
const Type_handler *
Type_handler::string_type_handler(uint max_octet_length) const
{
  if (max_octet_length >= 16777216)
    return &type_handler_long_blob;
  else if (max_octet_length >= 65536)
    return &type_handler_medium_blob;
  return &type_handler_varchar;
}


/**
  This method is used by:
  - Item_sum_hybrid, e.g. MAX(item), MIN(item).
  - Item_func_set_user_var
*/
const Type_handler *
Type_handler_string_result::type_handler_adjusted_to_max_octet_length(
                                                        uint max_octet_length,
                                                        CHARSET_INFO *cs) const
{
  if (max_octet_length / cs->mbmaxlen <= CONVERT_IF_BIGGER_TO_BLOB)
    return &type_handler_varchar; // See also Item::too_big_for_varchar()
  if (max_octet_length >= 16777216)
    return &type_handler_long_blob;
  else if (max_octet_length >= 65536)
    return &type_handler_medium_blob;
  return &type_handler_blob;
}


const Type_handler *
Type_handler_hybrid_field_type::get_handler_by_result_type(Item_result type)
                                                           const
{
  switch (type) {
  case REAL_RESULT:       return &type_handler_double;
  case INT_RESULT:        return &type_handler_longlong;
  case DECIMAL_RESULT:    return &type_handler_newdecimal;
  case STRING_RESULT:     return &type_handler_long_blob;
  case TIME_RESULT:       return &type_handler_datetime;
  case ROW_RESULT:
    DBUG_ASSERT(0);
  }
  return &type_handler_string;
}


Type_handler_hybrid_field_type::Type_handler_hybrid_field_type()
  :m_type_handler(&type_handler_double)
{
}


/**
  This method is used in Item context, e.g. in hybrid type functions
  like COALESCE, and does the following mapping:

  - CREATE TABLE t1 AS SELECT COALESCE(enum_of_set_column) FROM t2;
    creates a VARCHAR column. This may probably change in the future,
    to preserve the original type when it's possible.

  - CREATE TABLE t1 AS SELECT COALESCE(old_field) FROM t2;
    converts old types to new ones.
*/
const Type_handler *
Type_handler::get_handler_by_field_type(enum_field_types type)
{
  switch (type) {
  case MYSQL_TYPE_VAR_STRING:  return &type_handler_varchar; // Map to VARCHAR
  case MYSQL_TYPE_ENUM:        return &type_handler_varchar; // Map to VARCHAR
  case MYSQL_TYPE_SET:         return &type_handler_varchar; // Map to VARCHAR
  case MYSQL_TYPE_TIMESTAMP:   return &type_handler_timestamp2;// Map to timestamp2
  case MYSQL_TYPE_TIME:        return &type_handler_time2;     // Map to time2
  case MYSQL_TYPE_DATETIME:    return &type_handler_datetime2; // Map to datetime2
  case MYSQL_TYPE_DATE:        return &type_handler_newdate;   // Map to newdate
  case MYSQL_TYPE_NEWDATE:
    /*
      NEWDATE is actually a real_type(), not a field_type(),
      but it's used around the code in field_type() context.
      We should probably clean up the code not to use MYSQL_TYPE_NEWDATE
      in field_type() context and add DBUG_ASSERT(0) here.
    */
    return &type_handler_newdate;
  default:
    break;
  }
  return get_handler_by_real_type(type);
}


const Type_handler *
Type_handler::get_handler_by_real_type(enum_field_types type)
{
  /*
    VAR_STRING is actually a field_type(), not a real_type(),
    but it's used around the code in real_type() context.
    We should clean up the code and add DBUG_ASSERT(0) here.
  */
  if (type == MYSQL_TYPE_VAR_STRING)
    return &type_handler_string;
  return Type_handlers.handler(type);
}


bool
Type_handler::check_column_definition(THD *thd, Column_definition *def) const
{
  return def->check_traditional_type(thd);
}


/**
  Create a DOUBLE field by default.
*/
Field *
Type_handler::make_num_distinct_aggregator_field(MEM_ROOT *mem_root,
                                                 const Item *item) const
{
  return new(mem_root)
         Field_double(NULL, item->max_length,
                      (uchar *) (item->maybe_null ? "" : 0),
                      item->maybe_null ? 1 : 0, Field::NONE,
                      item->name, item->decimals, 0, item->unsigned_flag);
}


Field *
Type_handler_float::make_num_distinct_aggregator_field(MEM_ROOT *mem_root,
                                                       const Item *item)
                                                       const
{
  return new(mem_root)
         Field_float(NULL, item->max_length,
                     (uchar *) (item->maybe_null ? "" : 0),
                     item->maybe_null ? 1 : 0, Field::NONE,
                     item->name, item->decimals, 0, item->unsigned_flag);
}


Field *
Type_handler_decimal_result::make_num_distinct_aggregator_field(
                                                            MEM_ROOT *mem_root,
                                                            const Item *item)
                                                            const
{
  DBUG_ASSERT(item->decimals <= DECIMAL_MAX_SCALE);
  return new (mem_root)
         Field_new_decimal(NULL, item->max_length,
                           (uchar *) (item->maybe_null ? "" : 0),
                           item->maybe_null ? 1 : 0, Field::NONE,
                           item->name, item->decimals, 0, item->unsigned_flag);
}


Field *
Type_handler_int_result::make_num_distinct_aggregator_field(MEM_ROOT *mem_root,
                                                            const Item *item)
                                                            const
{
  /**
    Make a longlong field for all INT-alike types. It could create
    smaller fields for TINYINT, SMALLINT, MEDIUMINT, INT though.
  */
  return new(mem_root)
         Field_longlong(NULL, item->max_length,
                        (uchar *) (item->maybe_null ? "" : 0),
                        item->maybe_null ? 1 : 0, Field::NONE,
                        item->name, 0, item->unsigned_flag);
}


/***********************************************************************/

#define TMPNAME ""

Field *Type_handler_tiny::make_conversion_table_field(TABLE *table,
                                                      uint metadata,
                                                      const Field *target)
                                                      const
{
  /*
    As we don't know if the integer was signed or not on the master,
    assume we have same sign on master and slave.  This is true when not
    using conversions so it should be true also when using conversions.
  */
  bool unsigned_flag= ((Field_num*) target)->unsigned_flag;
  return new (table->in_use->mem_root)
         Field_tiny(NULL, 4 /*max_length*/, (uchar *) "", 1, Field::NONE,
                    TMPNAME, 0/*zerofill*/, unsigned_flag);
}


Field *Type_handler_short::make_conversion_table_field(TABLE *table,
                                                       uint metadata,
                                                       const Field *target)
                                                       const
{
  bool unsigned_flag= ((Field_num*) target)->unsigned_flag;
  return new (table->in_use->mem_root)
         Field_short(NULL, 6 /*max_length*/, (uchar *) "", 1, Field::NONE,
                     TMPNAME, 0/*zerofill*/, unsigned_flag);
}


Field *Type_handler_int24::make_conversion_table_field(TABLE *table,
                                                       uint metadata,
                                                       const Field *target)
                                                       const
{
  bool unsigned_flag= ((Field_num*) target)->unsigned_flag;
  return new (table->in_use->mem_root)
         Field_medium(NULL, 9 /*max_length*/, (uchar *) "", 1, Field::NONE,
                      TMPNAME, 0/*zerofill*/, unsigned_flag);
}


Field *Type_handler_long::make_conversion_table_field(TABLE *table,
                                                      uint metadata,
                                                      const Field *target)
                                                      const
{
  bool unsigned_flag= ((Field_num*) target)->unsigned_flag;
  return new (table->in_use->mem_root)
         Field_long(NULL, 11 /*max_length*/, (uchar *) "", 1, Field::NONE,
         TMPNAME, 0/*zerofill*/, unsigned_flag);
}


Field *Type_handler_longlong::make_conversion_table_field(TABLE *table,
                                                          uint metadata,
                                                          const Field *target)
                                                          const
{
  bool unsigned_flag= ((Field_num*) target)->unsigned_flag;
  return new (table->in_use->mem_root)
         Field_longlong(NULL, 20 /*max_length*/,(uchar *) "", 1, Field::NONE,
                        TMPNAME, 0/*zerofill*/, unsigned_flag);
}



Field *Type_handler_float::make_conversion_table_field(TABLE *table,
                                                       uint metadata,
                                                       const Field *target)
                                                       const
{
  return new (table->in_use->mem_root)
         Field_float(NULL, 12 /*max_length*/, (uchar *) "", 1, Field::NONE,
                     TMPNAME, 0/*dec*/, 0/*zerofill*/, 0/*unsigned_flag*/);
}


Field *Type_handler_double::make_conversion_table_field(TABLE *table,
                                                        uint metadata,
                                                        const Field *target)
                                                        const
{
  return new (table->in_use->mem_root)
         Field_double(NULL, 22 /*max_length*/, (uchar *) "", 1, Field::NONE,
                      TMPNAME, 0/*dec*/, 0/*zerofill*/, 0/*unsigned_flag*/);
}


Field *Type_handler_newdecimal::make_conversion_table_field(TABLE *table,
                                                            uint metadata,
                                                            const Field *target)
                                                            const
{
  int  precision= metadata >> 8;
  uint decimals= metadata & 0x00ff;
  uint32 max_length= my_decimal_precision_to_length(precision, decimals, false);
  DBUG_ASSERT(decimals <= DECIMAL_MAX_SCALE);
  return new (table->in_use->mem_root)
         Field_new_decimal(NULL, max_length, (uchar *) "", 1, Field::NONE,
                           TMPNAME, decimals, 0/*zerofill*/, 0/*unsigned*/);
}


Field *Type_handler_olddecimal::make_conversion_table_field(TABLE *table,
                                                            uint metadata,
                                                            const Field *target)
                                                            const
{
  sql_print_error("In RBR mode, Slave received incompatible DECIMAL field "
                  "(old-style decimal field) from Master while creating "
                  "conversion table. Please consider changing datatype on "
                  "Master to new style decimal by executing ALTER command for"
                  " column Name: %s.%s.%s.",
                  target->table->s->db.str,
                  target->table->s->table_name.str,
                  target->field_name);
  return NULL;
}


Field *Type_handler_year::make_conversion_table_field(TABLE *table,
                                                      uint metadata,
                                                      const Field *target)
                                                      const
{
  return new(table->in_use->mem_root)
         Field_year(NULL, 4, (uchar *) "", 1, Field::NONE, TMPNAME);
}


Field *Type_handler_null::make_conversion_table_field(TABLE *table,
                                                      uint metadata,
                                                      const Field *target)
                                                      const
{
  return new(table->in_use->mem_root)
         Field_null(NULL, 0, Field::NONE, TMPNAME, target->charset());
}


Field *Type_handler_timestamp::make_conversion_table_field(TABLE *table,
                                                           uint metadata,
                                                           const Field *target)
                                                           const
{
  // We assume TIMESTAMP(0)
  return new(table->in_use->mem_root)
         Field_timestamp(NULL, MAX_DATETIME_WIDTH, (uchar *) "", 1,
                         Field::NONE, TMPNAME, table->s);
}


Field *Type_handler_timestamp2::make_conversion_table_field(TABLE *table,
                                                            uint metadata,
                                                            const Field *target)
                                                            const
{
  return new(table->in_use->mem_root)
         Field_timestampf(NULL, (uchar *) "", 1, Field::NONE,
                          TMPNAME, table->s, metadata);
}


Field *Type_handler_newdate::make_conversion_table_field(TABLE *table,
                                                         uint metadata,
                                                         const Field *target)
                                                         const
{
  return new(table->in_use->mem_root)
         Field_newdate(NULL, (uchar *) "", 1, Field::NONE, TMPNAME);
}


Field *Type_handler_date::make_conversion_table_field(TABLE *table,
                                                      uint metadata,
                                                      const Field *target)
                                                      const
{
  return new(table->in_use->mem_root)
         Field_date(NULL, (uchar *) "", 1, Field::NONE, TMPNAME);
}


Field *Type_handler_time::make_conversion_table_field(TABLE *table,
                                                      uint metadata,
                                                      const Field *target)
                                                      const
{
  return new(table->in_use->mem_root)
         Field_time(NULL, MAX_TIME_WIDTH, (uchar *) "", 1,
                    Field::NONE, TMPNAME);
}


Field *Type_handler_time2::make_conversion_table_field(TABLE *table,
                                                       uint metadata,
                                                       const Field *target)
                                                       const
{
  return new(table->in_use->mem_root)
         Field_timef(NULL, (uchar *) "", 1, Field::NONE, TMPNAME, metadata);
}


Field *Type_handler_datetime::make_conversion_table_field(TABLE *table,
                                                          uint metadata,
                                                          const Field *target)
                                                          const
{
  return new(table->in_use->mem_root)
         Field_datetime(NULL, MAX_DATETIME_WIDTH, (uchar *) "", 1,
                        Field::NONE, TMPNAME);
}


Field *Type_handler_datetime2::make_conversion_table_field(TABLE *table,
                                                           uint metadata,
                                                           const Field *target)
                                                           const
{
  return new(table->in_use->mem_root)
         Field_datetimef(NULL, (uchar *) "", 1,
                         Field::NONE, TMPNAME, metadata);
}


Field *Type_handler_bit::make_conversion_table_field(TABLE *table,
                                                     uint metadata,
                                                     const Field *target)
                                                     const
{
  DBUG_ASSERT((metadata & 0xff) <= 7);
  uint32 max_length= 8 * (metadata >> 8U) + (metadata & 0x00ff);
  return new(table->in_use->mem_root)
         Field_bit_as_char(NULL, max_length, (uchar *) "", 1,
                           Field::NONE, TMPNAME);
}


Field *Type_handler_string::make_conversion_table_field(TABLE *table,
                                                        uint metadata,
                                                        const Field *target)
                                                        const
{
  /* This is taken from Field_string::unpack. */
  uint32 max_length= (((metadata >> 4) & 0x300) ^ 0x300) + (metadata & 0x00ff);
  return new(table->in_use->mem_root)
         Field_string(NULL, max_length, (uchar *) "", 1,
                      Field::NONE, TMPNAME, target->charset());
}


Field *Type_handler_varchar::make_conversion_table_field(TABLE *table,
                                                         uint metadata,
                                                         const Field *target)
                                                         const
{
  return new(table->in_use->mem_root)
         Field_varstring(NULL, metadata, HA_VARCHAR_PACKLENGTH(metadata),
                         (uchar *) "", 1, Field::NONE, TMPNAME,
                         table->s, target->charset());
}


Field *Type_handler_tiny_blob::make_conversion_table_field(TABLE *table,
                                                           uint metadata,
                                                           const Field *target)
                                                           const
{
  return new(table->in_use->mem_root)
         Field_blob(NULL, (uchar *) "", 1, Field::NONE, TMPNAME,
                    table->s, 1, target->charset());
}


Field *Type_handler_blob::make_conversion_table_field(TABLE *table,
                                                      uint metadata,
                                                      const Field *target)
                                                      const
{
  return new(table->in_use->mem_root)
         Field_blob(NULL, (uchar *) "", 1, Field::NONE, TMPNAME,
                    table->s, 2, target->charset());
}


Field *Type_handler_medium_blob::make_conversion_table_field(TABLE *table,
                                                           uint metadata,
                                                           const Field *target)
                                                           const
{
  return new(table->in_use->mem_root)
         Field_blob(NULL, (uchar *) "", 1, Field::NONE, TMPNAME,
                    table->s, 3, target->charset());
}


Field *Type_handler_long_blob::make_conversion_table_field(TABLE *table,
                                                           uint metadata,
                                                           const Field *target)
                                                           const
{
  return new(table->in_use->mem_root)
         Field_blob(NULL, (uchar *) "", 1, Field::NONE, TMPNAME,
                    table->s, 4, target->charset());
}


#ifdef HAVE_SPATIAL
Field *Type_handler_geometry::make_table_field(MEM_ROOT *root,
                                               TABLE_SHARE *share,
                                               const char *name,
                                               const Record_addr &rec,
                                               const Type_std_attributes &attr,
                                               const Type_ext_attributes &eattr,
                                               bool set_blob_packlength) const
{
  return new(root)
         Field_geom(rec.ptr, rec.null_ptr, rec.null_bit, Field::NONE, name,
                    share, 4, eattr.geometry_type(), 0/*TODO:SRID*/);
}


Field *Type_handler_geometry::make_conversion_table_field(TABLE *table,
                                                          uint metadata,
                                                          const Field *target)
                                                          const
{
  DBUG_ASSERT(target->type() == MYSQL_TYPE_GEOMETRY);
  /*
    We do not do not update feature_gis statistics here:
    status_var_increment(target->table->in_use->status_var.feature_gis);
    as this is only a temporary field.
    The statistics was already incremented when "target" was created.
  */
  return new(table->in_use->mem_root)
         Field_geom(NULL, (uchar *) "", 1, Field::NONE, TMPNAME, table->s, 4,
                    ((const Field_geom*) target)->geom_type,
                    ((const Field_geom*) target)->srid);
}
#endif

Field *Type_handler_enum::make_conversion_table_field(TABLE *table,
                                                      uint metadata,
                                                      const Field *target)
                                                      const
{
  DBUG_ASSERT(target->type() == MYSQL_TYPE_STRING);
  DBUG_ASSERT(target->real_type() == MYSQL_TYPE_ENUM);
  return new(table->in_use->mem_root)
         Field_enum(NULL, target->field_length,
                    (uchar *) "", 1, Field::NONE, TMPNAME,
                    metadata & 0x00ff/*pack_length()*/,
                    ((const Field_enum*) target)->typelib, target->charset());
}


Field *Type_handler_set::make_conversion_table_field(TABLE *table,
                                                     uint metadata,
                                                     const Field *target)
                                                     const
{
  DBUG_ASSERT(target->type() == MYSQL_TYPE_STRING);
  DBUG_ASSERT(target->real_type() == MYSQL_TYPE_SET);
  return new(table->in_use->mem_root)
         Field_set(NULL, target->field_length,
                   (uchar *) "", 1, Field::NONE, TMPNAME,
                   metadata & 0x00ff/*pack_length()*/,
                   ((const Field_enum*) target)->typelib, target->charset());
}


/*************************************************************************/
Field *Type_handler_olddecimal::make_table_field(MEM_ROOT *mem_root,
                                                 TABLE_SHARE *share,
                                                 const char *field_name,
                                                 const Record_addr &rec,
                                                 const Create_attr &attr) const
{
  return new (mem_root)
    Field_decimal(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
                  attr.unireg_check(), field_name,
                  f_decimals(attr.pack_flag()),
                  f_is_zerofill(attr.pack_flag()) != 0,
                  f_is_dec(attr.pack_flag()) == 0);
}


Field *Type_handler_newdecimal::make_table_field(MEM_ROOT *mem_root,
                                                 TABLE_SHARE *share,
                                                 const char *field_name,
                                                 const Record_addr &rec,
                                                 const Create_attr &attr) const
{
  return new (mem_root)
    Field_new_decimal(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
                      attr.unireg_check(), field_name,
                      f_decimals(attr.pack_flag()),
                      f_is_zerofill(attr.pack_flag()) != 0,
                      f_is_dec(attr.pack_flag()) == 0);
}


Field *Type_handler_float::make_table_field(MEM_ROOT *mem_root,
                                            TABLE_SHARE *share,
                                            const char *field_name,
                                            const Record_addr &rec,
                                            const Create_attr &attr) const
{
  return new (mem_root)
    Field_float(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
                attr.unireg_check(), field_name,
                f_decimals(attr.pack_flag()),
                f_is_zerofill(attr.pack_flag()) != 0,
                f_is_dec(attr.pack_flag())== 0);
}


Field *Type_handler_double::make_table_field(MEM_ROOT *mem_root,
                                             TABLE_SHARE *share,
                                             const char *field_name,
                                             const Record_addr &rec,
                                             const Create_attr &attr) const
{
  return new (mem_root)
    Field_double(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
                 attr.unireg_check(), field_name,
                 f_decimals(attr.pack_flag()),
                 f_is_zerofill(attr.pack_flag()) != 0,
                 f_is_dec(attr.pack_flag())== 0);
}


Field *Type_handler_tiny::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *field_name,
                                           const Record_addr &rec,
                                           const Create_attr &attr) const
{
  return new (mem_root)
    Field_tiny(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
               attr.unireg_check(), field_name,
               f_is_zerofill(attr.pack_flag()) != 0,
               f_is_dec(attr.pack_flag()) == 0);
}


Field *Type_handler_short::make_table_field(MEM_ROOT *mem_root,
                                            TABLE_SHARE *share,
                                            const char *field_name,
                                            const Record_addr &rec,
                                            const Create_attr &attr) const
{
  return new (mem_root)
    Field_short(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
                attr.unireg_check(), field_name,
                f_is_zerofill(attr.pack_flag()) != 0,
                f_is_dec(attr.pack_flag()) == 0);
}


Field *Type_handler_int24::make_table_field(MEM_ROOT *mem_root,
                                            TABLE_SHARE *share,
                                            const char *field_name,
                                            const Record_addr &rec,
                                            const Create_attr &attr) const
{
  return new (mem_root)
    Field_medium(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
                 attr.unireg_check(), field_name,
                 f_is_zerofill(attr.pack_flag()) != 0,
                 f_is_dec(attr.pack_flag()) == 0);
}


Field *Type_handler_long::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *field_name,
                                           const Record_addr &rec,
                                           const Create_attr &attr) const
{
  return new (mem_root)
    Field_long(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
               attr.unireg_check(), field_name,
               f_is_zerofill(attr.pack_flag()) != 0,
               f_is_dec(attr.pack_flag()) == 0);
}


Field *Type_handler_longlong::make_table_field(MEM_ROOT *mem_root,
                                               TABLE_SHARE *share,
                                               const char *field_name,
                                               const Record_addr &rec,
                                               const Create_attr &attr) const
{
  return new (mem_root)
    Field_longlong(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
                   attr.unireg_check(), field_name,
                   f_is_zerofill(attr.pack_flag()) != 0,
                   f_is_dec(attr.pack_flag()) == 0);
}



Field *Type_handler_timestamp::make_table_field(MEM_ROOT *mem_root,
                                                TABLE_SHARE *share,
                                                const char *field_name,
                                                const Record_addr &rec,
                                                const Create_attr &attr) const
{
  uint dec= attr.length() > MAX_DATETIME_WIDTH ?
            attr.length() - MAX_DATETIME_WIDTH - 1: 0;
  return new_Field_timestamp(mem_root, rec.ptr, rec.null_ptr, rec.null_bit,
                             attr.unireg_check(), field_name, share, dec);
}


Field *Type_handler_timestamp2::make_table_field(MEM_ROOT *mem_root,
                                                 TABLE_SHARE *share,
                                                 const char *field_name,
                                                 const Record_addr &rec,
                                                 const Create_attr &attr) const
{
  uint dec= attr.length() > MAX_DATETIME_WIDTH ?
            attr.length() - MAX_DATETIME_WIDTH - 1: 0;
  return new (mem_root)
    Field_timestampf(rec.ptr, rec.null_ptr, rec.null_bit,
                     attr.unireg_check(), field_name, share, dec);
}


Field *Type_handler_year::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *field_name,
                                           const Record_addr &rec,
                                           const Create_attr &attr) const
{
  return new (mem_root)
    Field_year(rec.ptr, attr.length(), rec.null_ptr, rec.null_bit,
               attr.unireg_check(), field_name);

}


Field *Type_handler_date::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *field_name,
                                           const Record_addr &rec,
                                           const Create_attr &attr) const
{
  return new (mem_root)
    Field_date(rec.ptr, rec.null_ptr, rec.null_bit,
               attr.unireg_check(), field_name);
}


Field *Type_handler_newdate::make_table_field(MEM_ROOT *mem_root,
                                              TABLE_SHARE *share,
                                              const char *field_name,
                                              const Record_addr &rec,
                                              const Create_attr &attr) const
{
  return new (mem_root)
    Field_newdate(rec.ptr, rec.null_ptr, rec.null_bit,
                  attr.unireg_check(), field_name);
}


Field *Type_handler_time::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *field_name,
                                           const Record_addr &rec,
                                           const Create_attr &attr) const
{
  uint dec= attr.length() > MIN_TIME_WIDTH ?
            attr.length() - MIN_TIME_WIDTH - 1: 0;
  return new_Field_time(mem_root, rec.ptr, rec.null_ptr, rec.null_bit,
                        attr.unireg_check(), field_name, dec);
}




Field *Type_handler_time2::make_table_field(MEM_ROOT *mem_root,
                                            TABLE_SHARE *share,
                                            const char *field_name,
                                            const Record_addr &rec,
                                            const Create_attr &attr) const
{
  uint dec= attr.length() > MIN_TIME_WIDTH ?
            attr.length() - MIN_TIME_WIDTH - 1: 0;
  return new (mem_root)
    Field_timef(rec.ptr, rec.null_ptr, rec.null_bit,
                attr.unireg_check(), field_name, dec);
}


Field *Type_handler_datetime::make_table_field(MEM_ROOT *mem_root,
                                               TABLE_SHARE *share,
                                               const char *field_name,
                                               const Record_addr &rec,
                                               const Create_attr &attr) const
{
  uint dec= attr.length() > MAX_DATETIME_WIDTH ?
            attr.length() - MAX_DATETIME_WIDTH - 1: 0;
  return new_Field_datetime(mem_root, rec.ptr, rec.null_ptr, rec.null_bit,
                            attr.unireg_check(), field_name, dec);
}


Field *Type_handler_datetime2::make_table_field(MEM_ROOT *mem_root,
                                                TABLE_SHARE *share,
                                                const char *field_name,
                                                const Record_addr &rec,
                                                const Create_attr &attr) const
{
  uint dec= attr.length() > MAX_DATETIME_WIDTH ?
            attr.length() - MAX_DATETIME_WIDTH - 1: 0;
  return new (mem_root)
    Field_datetimef(rec.ptr, rec.null_ptr, rec.null_bit,
                    attr.unireg_check(), field_name, dec);
}


Field *Type_handler_null::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *field_name,
                                           const Record_addr &rec,
                                           const Create_attr &attr) const
{
  return new (mem_root)
    Field_null(rec.ptr, attr.length(), attr.unireg_check(),
               field_name, attr.charset());
}


/*************************************************************************/

uint Type_handler::pack_flags_string(CHARSET_INFO *cs) const
{
  return (cs->state & MY_CS_BINSORT) ? FIELDFLAG_BINARY : 0;
}

uint Type_handler::pack_flags_numeric(uint flags, uint decimals) const
{
  return
    FIELDFLAG_NUMBER |
    (flags & UNSIGNED_FLAG ? 0 : FIELDFLAG_DECIMAL)  |
    (flags & ZEROFILL_FLAG ? FIELDFLAG_ZEROFILL : 0) |
    (decimals << FIELDFLAG_DEC_SHIFT);
}


bool Type_handler_null::prepare_column_definition(Column_definition *sql_field,
                                                  longlong table_flags) const
{
  sql_field->pack_flag= f_settype((uint) MYSQL_TYPE_NULL);
  return false;
}


bool Type_handler_blob::prepare_column_definition(Column_definition *sql_field,
                                                  longlong table_flags) const
{
  switch(real_field_type()) {
  case MYSQL_TYPE_BLOB:
  case MYSQL_TYPE_MEDIUM_BLOB:
  case MYSQL_TYPE_TINY_BLOB:
  case MYSQL_TYPE_LONG_BLOB:
    sql_field->pack_flag= FIELDFLAG_BLOB |
      pack_length_to_packflag(sql_field->pack_length -
                              portable_sizeof_char_ptr) |
      pack_flags_string(sql_field->charset);
    sql_field->length= 8;                     // Unireg field length
    sql_field->unireg_check= Field::BLOB_FIELD;
    return false;
  default:
    break;
  }
  DBUG_ASSERT(0);
  return true;
}


#ifdef HAVE_SPATIAL
bool
Type_handler_geometry::prepare_column_definition(Column_definition *sql_field,
                                                 longlong table_flags) const
{
  if (!(table_flags & HA_CAN_GEOMETRY))
  {
    my_printf_error(ER_CHECK_NOT_IMPLEMENTED, ER(ER_CHECK_NOT_IMPLEMENTED),
                    MYF(0), "GEOMETRY");
    return true;
  }
  sql_field->pack_flag=
    FIELDFLAG_GEOM |
    pack_length_to_packflag(sql_field->pack_length - portable_sizeof_char_ptr) |
    pack_flags_string(sql_field->charset);
  sql_field->length= 8;			// Unireg field length
  sql_field->unireg_check=Field::BLOB_FIELD;
  return false;
}
#endif /*HAVE_SPATIAL*/


/*
  Check TYPELIB (set or enum) for duplicates

  SYNOPSIS
    check_duplicates_in_interval()
    set_or_name   "SET" or "ENUM" string for warning message
    name	  name of the checked column
    typelib	  list of values for the column
    dup_val_count  returns count of duplicate elements

  DESCRIPTION
    This function prints an warning for each value in list
    which has some duplicates on its right

  RETURN VALUES
    0             ok
    1             Error
*/

static bool check_duplicates_in_interval(const char *set_or_name,
                                         const char *name, TYPELIB *typelib,
                                         CHARSET_INFO *cs,
                                         unsigned int *dup_val_count)
{
  TYPELIB tmp= *typelib;
  const char **cur_value= typelib->type_names;
  unsigned int *cur_length= typelib->type_lengths;
  *dup_val_count= 0;

  for ( ; tmp.count > 1; cur_value++, cur_length++)
  {
    tmp.type_names++;
    tmp.type_lengths++;
    tmp.count--;
    if (find_type2(&tmp, (const char*)*cur_value, *cur_length, cs))
    {
      THD *thd= current_thd;
      ErrConvString err(*cur_value, *cur_length, cs);
      if (current_thd->is_strict_mode())
      {
        my_error(ER_DUPLICATED_VALUE_IN_TYPE, MYF(0),
                 name, err.ptr(), set_or_name);
        return 1;
      }
      push_warning_printf(thd,Sql_condition::WARN_LEVEL_NOTE,
                          ER_DUPLICATED_VALUE_IN_TYPE,
                          ER_THD(thd, ER_DUPLICATED_VALUE_IN_TYPE),
                          name, err.ptr(), set_or_name);
      (*dup_val_count)++;
    }
  }
  return 0;
}


bool Type_handler_enum::prepare_column_definition(Column_definition *sql_field,
                                                  longlong table_flags) const
{
  unsigned int dup_val_count;
  sql_field->pack_flag= FIELDFLAG_INTERVAL |
                        pack_length_to_packflag(sql_field->pack_length) |
                        pack_flags_string(sql_field->charset);
  sql_field->unireg_check= Field::INTERVAL_FIELD;
  return check_duplicates_in_interval("ENUM",sql_field->field_name,
                                      sql_field->interval,
                                      sql_field->charset, &dup_val_count);
}


bool Type_handler_set::prepare_column_definition(Column_definition *sql_field,
                                                 longlong table_flags) const
{
  unsigned int dup_val_count;
  sql_field->pack_flag= FIELDFLAG_BITFIELD |
                        pack_length_to_packflag(sql_field->pack_length) |
                        pack_flags_string(sql_field->charset);
  sql_field->unireg_check= Field::BIT_FIELD;
  if (check_duplicates_in_interval("SET",sql_field->field_name,
                                   sql_field->interval,
                                   sql_field->charset, &dup_val_count))
    return true;
  /* Check that count of unique members is not more then 64 */
  if (sql_field->interval->count - dup_val_count > sizeof(longlong) * 8)
  {
     my_error(ER_TOO_BIG_SET, MYF(0), sql_field->field_name);
     return true;
  }
  return false;
}


bool
Type_handler_temporal_result::prepare_column_definition(Column_definition
                                                        *sql_field,
                                                        longlong table_flags)
                                                        const
{
  sql_field->pack_flag= f_settype((uint) sql_field->sql_type);
  return false;
}


bool
Type_handler_string::prepare_column_definition(Column_definition *sql_field,
                                               longlong table_flags) const
{
  sql_field->pack_flag= pack_flags_string(sql_field->charset);
  return false;
}


bool
Type_handler_varchar::prepare_column_definition(Column_definition *sql_field,
                                                longlong table_flags) const
{
#ifndef QQ_ALL_HANDLERS_SUPPORT_VARCHAR
  if (table_flags & HA_NO_VARCHAR)
  {
    /* convert VARCHAR to CHAR because handler is not yet up to date */
    sql_field->sql_type= MYSQL_TYPE_VAR_STRING;
    sql_field->pack_length=
      Type_handler_varchar::calc_pack_length((uint) sql_field->length);
    if ((sql_field->length / sql_field->charset->mbmaxlen) >
        MAX_FIELD_CHARLENGTH)
    {
      my_printf_error(ER_TOO_BIG_FIELDLENGTH, ER(ER_TOO_BIG_FIELDLENGTH),
                      MYF(0), sql_field->field_name,
                      static_cast<ulong>(MAX_FIELD_CHARLENGTH));
      return true;
    }
  }
#endif
  sql_field->pack_flag= pack_flags_string(sql_field->charset);
  return false;
}


bool
Type_handler_numeric::prepare_column_definition(Column_definition *sql_field,
                                                longlong table_flags) const
{
  sql_field->pack_flag=
    pack_flags_numeric(sql_field->flags, sql_field->decimals) |
    f_settype((uint) sql_field->sql_type);
  return false;
}


bool
Type_handler_newdecimal::prepare_column_definition(Column_definition *sql_field,
                                                longlong table_flags) const
{
  sql_field->pack_flag=
    pack_flags_numeric(sql_field->flags, sql_field->decimals);
  return false;
}


bool
Type_handler_timestamp::prepare_column_definition(Column_definition *sql_field,
                                                  longlong table_flags) const
{
  sql_field->pack_flag=
    pack_flags_numeric(sql_field->flags, 0) |
    f_settype((uint) sql_field->sql_type);
  return false;
}


bool
Type_handler_timestamp2::prepare_column_definition(Column_definition *sql_field,
                                                   longlong table_flags) const
{
  sql_field->pack_flag=
    pack_flags_numeric(sql_field->flags, sql_field->decimals) |
    f_settype((uint) sql_field->sql_type);
  return false;
}


/*************************************************************************/

Field *Type_handler_tiny::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *name,
                                           const Record_addr &rec,
                                           const Type_std_attributes &attr,
                                           const Type_ext_attributes &eattr,
                                           bool set_blob_packlength) const
{
  return new (mem_root)
         Field_tiny(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                    Field::NONE, name, 0, attr.unsigned_flag);
}


Field *Type_handler_short::make_table_field(MEM_ROOT *mem_root,
                                            TABLE_SHARE *share,
                                            const char *name,
                                            const Record_addr &rec,
                                            const Type_std_attributes &attr,
                                            const Type_ext_attributes &eattr,
                                            bool set_blob_packlength) const
{
  return new (mem_root)
         Field_short(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                     Field::NONE, name, 0, attr.unsigned_flag);
}


Field *Type_handler_long::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *name,
                                           const Record_addr &rec,
                                           const Type_std_attributes &attr,
                                           const Type_ext_attributes &eattr,
                                           bool set_blob_packlength) const
{
  return new (mem_root)
         Field_long(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                    Field::NONE, name, 0, attr.unsigned_flag);
}


Field *Type_handler_longlong::make_table_field(MEM_ROOT *mem_root,
                                               TABLE_SHARE *share,
                                               const char *name,
                                               const Record_addr &rec,
                                               const Type_std_attributes &attr,
                                               const Type_ext_attributes &eattr,
                                               bool set_blob_packlength) const
{
  return new (mem_root)
         Field_longlong(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                        Field::NONE, name, 0, attr.unsigned_flag);
}


Field *Type_handler_float::make_table_field(MEM_ROOT *mem_root,
                                            TABLE_SHARE *share,
                                            const char *name,
                                            const Record_addr &rec,
                                            const Type_std_attributes &attr,
                                            const Type_ext_attributes &eattr,
                                            bool set_blob_packlength) const
{
  return new (mem_root)
         Field_float(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                     Field::NONE, name, attr.decimals, 0, attr.unsigned_flag);
}


Field *Type_handler_double::make_table_field(MEM_ROOT *mem_root,
                                             TABLE_SHARE *share,
                                             const char *name,
                                             const Record_addr &rec,
                                             const Type_std_attributes &attr,
                                             const Type_ext_attributes &eattr,
                                             bool set_blob_packlength) const
{
  return new (mem_root)
         Field_double(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                      Field::NONE, name, attr.decimals, 0, attr.unsigned_flag);
}


Field *Type_handler_int24::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *name,
                                           const Record_addr &rec,
                                           const Type_std_attributes &attr,
                                           const Type_ext_attributes &eattr,
                                           bool set_blob_packlength) const
{
  return new (mem_root)
         Field_medium(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                      Field::NONE, name, 0, attr.unsigned_flag);
}


Field *Type_handler_date::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *name,
                                           const Record_addr &rec,
                                           const Type_std_attributes &attr,
                                           const Type_ext_attributes &eattr,
                                           bool set_blob_packlength) const
{
  return new (mem_root)
         Field_newdate(rec.ptr, rec.null_ptr, rec.null_bit, Field::NONE, name);
}



Field *Type_handler_newdate::make_table_field(MEM_ROOT *mem_root,
                                              TABLE_SHARE *share,
                                              const char *name,
                                              const Record_addr &rec,
                                              const Type_std_attributes &attr,
                                             const Type_ext_attributes &eattr,
                                              bool set_blob_packlength) const
{
  return new (mem_root)
         Field_newdate(rec.ptr, rec.null_ptr, rec.null_bit, Field::NONE, name);
}


Field *Type_handler_time::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *name,
                                           const Record_addr &rec,
                                           const Type_std_attributes &attr,
                                           const Type_ext_attributes &eattr,
                                           bool set_blob_packlength) const
{
  return new_Field_time(mem_root, rec.ptr, rec.null_ptr, rec.null_bit,
                        Field::NONE, name, attr.decimals);
}


Field *Type_handler_time2::make_table_field(MEM_ROOT *mem_root,
                                            TABLE_SHARE *share,
                                            const char *name,
                                            const Record_addr &rec,
                                            const Type_std_attributes &attr,
                                            const Type_ext_attributes &eattr,
                                            bool set_blob_packlength) const
{
  return new_Field_time(mem_root, rec.ptr, rec.null_ptr, rec.null_bit,
                        Field::NONE, name, attr.decimals);
}


Field *Type_handler_timestamp::make_table_field(MEM_ROOT *mem_root,
                                                TABLE_SHARE *share,
                                                const char *name,
                                                const Record_addr &rec,
                                                const Type_std_attributes &attr,
                                                const Type_ext_attributes &eattr,
                                                bool set_blob_packlength) const
{
  return new_Field_timestamp(mem_root, rec.ptr, rec.null_ptr, rec.null_bit,
                             Field::NONE, name, 0, attr.decimals);
}


Field *Type_handler_timestamp2::make_table_field(MEM_ROOT *mem_root,
                                                 TABLE_SHARE *share,
                                                 const char *name,
                                                 const Record_addr &rec,
                                                 const Type_std_attributes &attr,
                                                 const Type_ext_attributes &eattr,
                                                 bool set_blob_packlength) const
{
  return new_Field_timestamp(mem_root, rec.ptr, rec.null_ptr, rec.null_bit,
                             Field::NONE, name, 0, attr.decimals);
}


Field *Type_handler_datetime::make_table_field(MEM_ROOT *mem_root,
                                               TABLE_SHARE *share,
                                               const char *name,
                                               const Record_addr &rec,
                                               const Type_std_attributes &attr,
                                               const Type_ext_attributes &eattr,
                                               bool set_blob_packlength) const
{
  return new_Field_datetime(mem_root, rec.ptr, rec.null_ptr, rec.null_bit,
                            Field::NONE, name, attr.decimals);
}


Field *Type_handler_datetime2::make_table_field(MEM_ROOT *mem_root,
                                               TABLE_SHARE *share,
                                               const char *name,
                                               const Record_addr &rec,
                                               const Type_std_attributes &attr,
                                               const Type_ext_attributes &eattr,
                                               bool set_blob_packlength) const
{
  return new_Field_datetime(mem_root, rec.ptr, rec.null_ptr, rec.null_bit,
                            Field::NONE, name, attr.decimals);
}


Field *Type_handler_year::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *name,
                                           const Record_addr &rec,
                                           const Type_std_attributes &attr,
                                           const Type_ext_attributes &eattr,
                                           bool set_blob_packlength) const
{
  return new (mem_root)
         Field_year(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                    Field::NONE, name);
}


Field *Type_handler_bit::make_table_field(MEM_ROOT *mem_root,
                                          TABLE_SHARE *share,
                                          const char *name,
                                          const Record_addr &rec,
                                          const Type_std_attributes &attr,
                                          const Type_ext_attributes &eattr,
                                          bool set_blob_packlength) const
{
  return new (mem_root)
         Field_bit_as_char(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                           Field::NONE, name);
}


Field *Type_handler_null::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *name,
                                           const Record_addr &rec,
                                           const Type_std_attributes &attr,
                                           const Type_ext_attributes &eattr,
                                           bool set_blob_packlength) const
{
  DBUG_ASSERT(attr.max_length == 0);
  return new (mem_root)
         Field_string(name, rec, 0 /*max_length*/, attr.collation.collation);
}


Field *Type_handler_blob::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *name,
                                           const Record_addr &rec,
                                           const Type_std_attributes &attr,
                                           const Type_ext_attributes &eattr,
                                           bool set_blob_packlength) const
{
  return new (mem_root)
         Field_blob(name, rec, attr.max_length, attr.collation.collation,
                    set_blob_packlength);
}


Field *
Type_handler_string_result::make_table_field(MEM_ROOT *mem_root,
                                             TABLE_SHARE *share,
                                             const char *name,
                                             const Record_addr &rec,
                                             const Type_std_attributes &attr,
                                             const Type_ext_attributes &eattr,
                                             bool set_blob_packlength) const
{
  return attr.make_string_field(mem_root, share, name, rec);
}


Field *Type_handler_enum::make_table_field(MEM_ROOT *mem_root,
                                           TABLE_SHARE *share,
                                           const char *name,
                                           const Record_addr &rec,
                                           const Type_std_attributes &attr,
                                           const Type_ext_attributes &eattr,
                                           bool set_blob_packlength) const
{
  return eattr.typelib() ?
    new Field_enum(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                   Field::NONE, name,
                   get_enum_pack_length(eattr.typelib()->count),
                   eattr.typelib(),
                   attr.collation.collation) :
    attr.make_string_field(mem_root, share, name, rec);
}


Field *Type_handler_set::make_table_field(MEM_ROOT *mem_root,
                                          TABLE_SHARE *share,
                                          const char *name,
                                          const Record_addr &rec,
                                          const Type_std_attributes &attr,
                                          const Type_ext_attributes &eattr,
                                          bool set_blob_packlength) const
{
  return eattr.typelib() ?
    new Field_set(rec.ptr, attr.max_length, rec.null_ptr, rec.null_bit,
                  Field::NONE, name,
                  get_enum_pack_length(eattr.typelib()->count),
                  eattr.typelib(),
                  attr.collation.collation) :
    attr.make_string_field(mem_root, share, name, rec);
}


Field *
Type_handler_newdecimal::make_table_field(MEM_ROOT *mem_root,
                                          TABLE_SHARE *share,
                                          const char *name,
                                          const Record_addr &rec,
                                          const Type_std_attributes &attr,
                                          const Type_ext_attributes &eattr,
                                          bool set_blob_packlength) const
{
  DBUG_ASSERT(eattr.decimal_int_part() > 0);
  DBUG_ASSERT(eattr.decimal_int_part() + attr.decimals + 1 <= attr.max_length);
  uint32 len= my_decimal_precision_to_length(eattr.decimal_int_part() + attr.decimals,
                                             attr.decimals,
                                             attr.unsigned_flag);
  return new (mem_root)
             Field_new_decimal(rec.ptr, len, rec.null_ptr, rec.null_bit,
                               Field::NONE, name, attr.decimals,
                               0/*zero_arg*/, attr.unsigned_flag);
}


Field *
Type_handler_olddecimal::make_table_field(MEM_ROOT *mem_root,
                                          TABLE_SHARE *share,
                                          const char *name,
                                          const Record_addr &rec,
                                          const Type_std_attributes &attr,
                                          const Type_ext_attributes &eattr,
                                          bool set_blob_packlength) const
{
  return type_handler_newdecimal.make_table_field(mem_root, share, name,
                                                  rec, attr, eattr,
                                                  set_blob_packlength);
}

/*************************************************************************/

String *
Type_handler_string_result::Item_func_hybrid_field_type_val_str(
                                              Item_func_hybrid_field_type *item,
                                              String *str) const
{
  return item->val_str_from_str_op(str);
}


String *
Type_handler_decimal_result::Item_func_hybrid_field_type_val_str(
                                              Item_func_hybrid_field_type *item,
                                              String *str) const
{
  return item->val_str_from_dec_op(str);
}


String *
Type_handler_int_result::Item_func_hybrid_field_type_val_str(
                                              Item_func_hybrid_field_type *item,
                                              String *str) const
{
  return item->val_str_from_int_op(str);
}


String *
Type_handler_real_result::Item_func_hybrid_field_type_val_str(
                                              Item_func_hybrid_field_type *item,
                                              String *str) const
{
  return item->val_str_from_real_op(str);
}


String *
Type_handler_temporal_result::Item_func_hybrid_field_type_val_str(
                                              Item_func_hybrid_field_type *item,
                                              String *str) const
{
  return item->val_str_from_temp_op(str);
}

/************************************************************************/

longlong Type_handler_int_result::
Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const
{
  return item->int_op();
}

longlong Type_handler_real_result::
Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const
{
  return (longlong) rint(item->real_op());
}

longlong Type_handler_decimal_result::
Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const
{
  return item->val_int_from_dec_op();
}

longlong Type_handler_temporal_result::
Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const
{
  return item->val_int_from_temp_op();
}

longlong Type_handler_string_result::
Item_func_hybrid_field_type_val_int(Item_func_hybrid_field_type *item) const
{
  return item->val_int_from_str_op();
}


/**************************************************************************/


double Type_handler_int_result::
Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const
{
  return item->val_real_from_int_op();
}

double Type_handler_real_result::
Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const
{
  return item->real_op();
}

double Type_handler_decimal_result::
Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const
{
  return item->val_real_from_dec_op();
}

double Type_handler_temporal_result::
Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const
{
  return item->val_real_from_temp_op();
}

double Type_handler_string_result::
  Item_func_hybrid_field_type_val_real(Item_func_hybrid_field_type *item) const
{
  return item->val_real_from_str_op();
}

/*****************************************************************************/

my_decimal* Type_handler_decimal_result::
Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                        my_decimal *to) const
{
  return item->val_decimal_from_dec_op(to);
}

my_decimal* Type_handler_int_result::
Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                        my_decimal *to) const
{
  return item->val_decimal_from_int_op(to);
}

my_decimal* Type_handler_real_result::
Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                        my_decimal *to) const
{
  return item->val_decimal_from_real_op(to);
}

my_decimal* Type_handler_temporal_result::
Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                        my_decimal *to) const
{
  return item->val_decimal_from_temp_op(to);
}

my_decimal* Type_handler_string_result::
Item_func_hybrid_field_type_val_decimal(Item_func_hybrid_field_type *item,
                                        my_decimal *to) const
{
  return item->val_decimal_from_str_op(to);
}

/*************************************************************************/
bool
Type_handler_decimal_result::
Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                     MYSQL_TIME *ltime, ulonglong fuzzydate)
                                     const
{
  return item->get_date_from_dec_op(ltime, fuzzydate);
}

bool
Type_handler_int_result::
Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                     MYSQL_TIME *ltime, ulonglong fuzzydate)
                                     const
{
  return item->get_date_from_int_op(ltime, fuzzydate);
}

bool
Type_handler_real_result::
Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                     MYSQL_TIME *ltime, ulonglong fuzzydate)
                                     const
{
  return item->get_date_from_real_op(ltime, fuzzydate);
}

bool
Type_handler_temporal_result::
Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                     MYSQL_TIME *ltime, ulonglong fuzzydate)
                                     const
{
  return item->date_op(ltime,
                       fuzzydate |
                       (field_type() == MYSQL_TYPE_TIME ? TIME_TIME_ONLY : 0));
}


bool
Type_handler_string_result::
Item_func_hybrid_field_type_get_date(Item_func_hybrid_field_type *item,
                                     MYSQL_TIME *ltime, ulonglong fuzzydate)
                                     const
{
  return item->get_date_from_str_op(ltime, fuzzydate);
}

/*************************************************************************/
bool Type_handler_int_result::set_comparator_func(Arg_comparator *cmp) const
{
  return cmp->set_cmp_func_int();
}

bool Type_handler_real_result::set_comparator_func(Arg_comparator *cmp) const
{
  return cmp->set_cmp_func_real();
}

bool Type_handler_decimal_result::set_comparator_func(Arg_comparator *cmp) const
{
  return cmp->set_cmp_func_decimal();
}

bool Type_handler_string_result::set_comparator_func(Arg_comparator *cmp) const
{
  return cmp->set_cmp_func_string();
}

bool Type_handler_temporal_result::set_comparator_func(Arg_comparator *cmp) const
{
  return cmp->set_cmp_func_temporal();
}

/*************************************************************************/

Item_cache *
Type_handler_int_result::make_cache_item(THD *thd, const Item *item) const
{
  return new (thd->mem_root) Item_cache_int(thd, item->field_type());
}

Item_cache *
Type_handler_real_result::make_cache_item(THD *thd, const Item *item) const
{
  return new (thd->mem_root) Item_cache_real(thd);
}

Item_cache *
Type_handler_decimal_result::make_cache_item(THD *thd, const Item *item) const
{
  return new (thd->mem_root) Item_cache_decimal(thd);
}

Item_cache *
Type_handler_string_result::make_cache_item(THD *thd, const Item *item) const
{
  return new (thd->mem_root) Item_cache_str(thd, item);
}

Item_cache *
Type_handler_temporal_result::make_cache_item(THD *thd, const Item *item) const
{
  return new (thd->mem_root) Item_cache_temporal(thd, item->field_type());
}

/*************************************************************************/

bool Type_handler_string_result::
       Item_func_between_fix_length_and_dec(Item_func_between *func) const
{
  return func->fix_length_and_dec_traditional();
}

bool Type_handler_temporal_result::
       Item_func_between_fix_length_and_dec(Item_func_between *func) const
{
  return func->fix_length_and_dec_traditional();

}

bool Type_handler_int_result::
       Item_func_between_fix_length_and_dec(Item_func_between *func) const
{
  return func->fix_length_and_dec_traditional();

}

bool Type_handler_real_result::
       Item_func_between_fix_length_and_dec(Item_func_between *func) const
{
  return func->fix_length_and_dec_traditional();

}

bool Type_handler_decimal_result::
       Item_func_between_fix_length_and_dec(Item_func_between *func) const
{
  return func->fix_length_and_dec_traditional();

}

longlong Type_handler_string_result::
           Item_func_between_val_int(Item_func_between *func) const
{
  return func->val_int_cmp_string();
}

longlong Type_handler_temporal_result::
           Item_func_between_val_int(Item_func_between *func) const
{
  return func->val_int_cmp_temporal();
}

longlong Type_handler_int_result::
           Item_func_between_val_int(Item_func_between *func) const
{
  return func->val_int_cmp_int();
}

longlong Type_handler_real_result::
           Item_func_between_val_int(Item_func_between *func) const
{
  return func->val_int_cmp_real();
}

longlong Type_handler_decimal_result::
           Item_func_between_val_int(Item_func_between *func) const
{
  return func->val_int_cmp_decimal();
}

/*************************************************************************/

/**
   MAX(str_field) converts ENUM/SET to CHAR, and preserve all other types
   for Fields.
   QQ: This works differently from UNION, which preserve the exact data
   type for ENUM/SET, if the joined ENUM/SET fields are equally defined.
   Perhaps should be fixed.
   MAX(str_item) chooses the best suitable string type.
*/
bool Type_handler_string_result::
       Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const
{
  Item *item= func->arguments()[0];
  Item *item2= item->real_item();
  func->Type_std_attributes::set(item);
  if (item2->type() == Item::FIELD_ITEM)
  {
    // Fields: convert ENUM/SET to CHAR
    func->set_handler_by_field_type(item->field_type());
  }
  else
  {
    /*
      Items: choose VARCHAR / BLOB / MEDIUMBLOB / LONGBLOB, depending on length.
    */
    func->set_handler(type_handler_varchar.
          type_handler_adjusted_to_max_octet_length(func->max_length,
                                                    func->collation.collation));
  }
  return false;
}


/**
  MAX/MIN for the traditional numeric types preserve the exact data type
  from Fields, but do not preserve the exact type from Items:
    MAX(float_field)              -> FLOAT
    MAX(smallint_field)           -> LONGLONG
    MAX(COALESCE(float_field))    -> DOUBLE
    MAX(COALESCE(smallint_field)) -> LONGLONG
  QQ: Items should probably be fixed to preserve the exact type.
*/
bool Type_handler_numeric::
       Item_sum_hybrid_fix_length_and_dec_numeric(Item_sum_hybrid *func,
                                                  const Type_handler *handler)
                                                  const
{
  Item *item= func->arguments()[0];
  Item *item2= item->real_item();
  func->Type_std_attributes::set(item);
  if (item2->type() == Item::FIELD_ITEM)
    func->set_handler_by_field_type(item2->field_type());
  else
    func->set_handler(handler);
  return false;
}


bool Type_handler_int_result::
       Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const
{
  return Item_sum_hybrid_fix_length_and_dec_numeric(func,
                                                    &type_handler_longlong);
}


bool Type_handler_real_result::
       Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const
{
  (void) Item_sum_hybrid_fix_length_and_dec_numeric(func,
                                                    &type_handler_double);
  func->max_length= func->float_length(func->decimals);
  return false;
}


bool Type_handler_decimal_result::
       Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const
{
  return Item_sum_hybrid_fix_length_and_dec_numeric(func,
                                                    &type_handler_newdecimal);
}


/**
  Traditional temporal types always preserve the type of the argument.
*/
bool Type_handler_temporal_result::
       Item_sum_hybrid_fix_length_and_dec(Item_sum_hybrid *func) const
{
  Item *item= func->arguments()[0];
  func->Type_std_attributes::set(item);
  func->set_handler_by_field_type(item->field_type());
  return false;
}

/*************************************************************************/

uint32
Type_handler_temporal_result::
  calc_display_length(const Type_std_attributes *attr) const
{
  return attr->max_length;
}

uint32
Type_handler_string_result::
  calc_display_length(const Type_std_attributes *attr) const
{
  return attr->max_length;
}

uint32
Type_handler_decimal_result::
  calc_display_length(const Type_std_attributes *attr) const
{
  return attr->max_length;
}

uint32
Type_handler_year::calc_display_length(const Type_std_attributes *attr) const
{
  return attr->max_length;
}

uint32
Type_handler_bit::calc_display_length(const Type_std_attributes *attr) const
{
  return attr->max_length;
}

/*************************************************************************/

int Type_handler_time::Item_save_in_field(Item *item, Field *field,
                                          bool no_conversions) const
{
  return item->save_time_in_field(field, no_conversions);
}

int Type_handler_time2::Item_save_in_field(Item *item, Field *field,
                                           bool no_conversions) const
{
  return item->save_time_in_field(field, no_conversions);
}


int Type_handler_date::Item_save_in_field(Item *item, Field *field,
                                          bool no_conversions) const
{
  return item->save_date_in_field(field, no_conversions);
}

int Type_handler_newdate::Item_save_in_field(Item *item, Field *field,
                                             bool no_conversions) const
{
  return item->save_date_in_field(field, no_conversions);
}


int Type_handler_datetime::Item_save_in_field(Item *item, Field *field,
                                               bool no_conversions) const
{
  return item->save_date_in_field(field, no_conversions);
}

int Type_handler_datetime2::Item_save_in_field(Item *item, Field *field,
                                               bool no_conversions) const
{
  return item->save_date_in_field(field, no_conversions);
}

int Type_handler_timestamp::Item_save_in_field(Item *item, Field *field,
                                               bool no_conversions) const
{
  return item->save_date_in_field(field, no_conversions);
}

int Type_handler_timestamp2::Item_save_in_field(Item *item, Field *field,
                                                bool no_conversions) const
{
  return item->save_date_in_field(field, no_conversions);
}


int Type_handler_string_result::Item_save_in_field(Item *item, Field *field,
                                                   bool no_conversions) const
{
  return item->save_str_in_field(field, no_conversions);
}


int Type_handler_real_result::Item_save_in_field(Item *item, Field *field,
                                                 bool no_conversions) const
{
  double nr= item->val_real();
  if (item->null_value)
    return set_field_to_null_with_conversions(field, no_conversions);
  field->set_notnull();
  return field->store(nr);
}


int Type_handler_decimal_result::Item_save_in_field(Item *item, Field *field,
                                                    bool no_conversions) const
{
  my_decimal decimal_value;
  my_decimal *value= item->val_decimal(&decimal_value);
  if (item->null_value)
    return set_field_to_null_with_conversions(field, no_conversions);
  field->set_notnull();
  return field->store_decimal(value);
}


int Type_handler_int_result::Item_save_in_field(Item *item, Field *field,
                                                bool no_conversions) const
{
  longlong nr= item->val_int();
  if (item->null_value)
    return set_field_to_null_with_conversions(field, no_conversions);
  field->set_notnull();
  return field->store(nr, item->unsigned_flag);
}

/*************************************************************************/

bool Type_handler_decimal_result::
       Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const
{
  return holder->join_attributes_decimal(thd, item);
}

bool Type_handler_int_result::Item_type_holder_join_attributes(THD *thd,
                                                    Item_type_holder *holder,
                                                    Item *item) const
{
  return holder->join_attributes_int(thd, item);
}

bool Type_handler_float::Item_type_holder_join_attributes(THD *thd,
                                                    Item_type_holder *holder,
                                                    Item *item) const
{
  return holder->join_attributes_real(thd, item, FLT_DIG, MAX_FLOAT_STR_LENGTH,
                                                 FLT_DIG + 6);
}

bool Type_handler_double::Item_type_holder_join_attributes(THD *thd,
                                                    Item_type_holder *holder,
                                                    Item *item) const
{
  return holder->join_attributes_real(thd, item, DBL_DIG, MAX_DOUBLE_STR_LENGTH,
                                                 DBL_DIG + 7);
}

bool Type_handler_temporal_result::Item_type_holder_join_attributes(THD *thd,
                                                    Item_type_holder *holder,
                                                    Item *item) const
{
  return holder->join_attributes_temporal(thd, item);
}

bool Type_handler_enum::Item_type_holder_join_attributes(THD *thd,
                                                    Item_type_holder *holder,
                                                    Item *item) const
{
  return holder->join_attributes_enum_or_set(thd, item);
}


bool Type_handler_set::Item_type_holder_join_attributes(THD *thd,
                                                    Item_type_holder *holder,
                                                    Item *item) const
{
  return holder->join_attributes_enum_or_set(thd, item);
}


bool Type_handler_string_result::Item_type_holder_join_attributes(THD *thd,
                                                    Item_type_holder *holder,
                                                    Item *item) const
{
  return holder->join_attributes_string(thd, item);
}

bool Type_handler_geometry::
       Item_type_holder_join_attributes(THD *thd, Item_type_holder *holder,
                                        Item *item) const
{
  return holder->join_attributes_geometry(thd, item);
}

/*************************************************************************/

String *
Type_handler_int_result::Item_func_hex_val_str_ascii(Item_func_hex *item,
                                                     String *str) const
{
  return item->val_str_ascii_from_val_int(str);
}

String *
Type_handler_decimal_result::Item_func_hex_val_str_ascii(Item_func_hex *item,
                                                         String *str) const
{
  return item->val_str_ascii_from_val_real(str);
}

String *
Type_handler_real_result::Item_func_hex_val_str_ascii(Item_func_hex *item,
                                                      String *str) const
{
  return item->val_str_ascii_from_val_real(str);
}


String *
Type_handler_temporal_result::Item_func_hex_val_str_ascii(Item_func_hex *item,
                                                          String *str) const
{
  return item->val_str_ascii_from_val_str(str);
}

String *
Type_handler_string_result::Item_func_hex_val_str_ascii(Item_func_hex *item,
                                                        String *str) const
{
  return item->val_str_ascii_from_val_str(str);
}

/*************************************************************************/

Type_handler_register::Type_handler_register()
  :m_min_type(256), m_max_type(0)
{
  add(&type_handler_tiny);
  add(&type_handler_short);
  add(&type_handler_long);
  add(&type_handler_int24);
  add(&type_handler_longlong);
  add(&type_handler_year);
  add(&type_handler_bit);
  add(&type_handler_float);
  add(&type_handler_double);

  add(&type_handler_time);
  add(&type_handler_time2);

  add(&type_handler_date);
  add(&type_handler_newdate);

  add(&type_handler_datetime);
  add(&type_handler_datetime2);

  add(&type_handler_timestamp);
  add(&type_handler_timestamp2);

  add(&type_handler_olddecimal);
  add(&type_handler_newdecimal);

  add(&type_handler_null);

  add(&type_handler_string);
  add(&type_handler_varchar);

  add(&type_handler_tiny_blob);
  add(&type_handler_medium_blob);
  add(&type_handler_long_blob);
  add(&type_handler_blob);

#ifdef HAVE_SPATIAL
  add(&type_handler_geometry);
#endif

  add(&type_handler_enum);
  add(&type_handler_set);
}

Type_handler_register Type_handlers;
