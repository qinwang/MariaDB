
#ifndef SQL_WINDOW_INCLUDED
#define SQL_WINDOW_INCLUDED

class Window_frame_bound : public Sql_alloc
{

public:
 
  enum Bound_precedence_type
  {
    PRECEDING,
    FOLLOWING
  };

  Bound_precedence_type precedence_type;

  Item *offset;

};


class Window_frame : public Sql_alloc
{
  
public:

  enum Frame_units
  {
    UNITS_ROWS,
    UNITS_RANGE
  };

  enum Frame_exclusion
  {
    EXCL_NONE,
    EXCL_CURRENT_ROW,
    EXCL_GROUP,
    EXCL_TIES
  };

  Frame_units units;

  Window_frame_bound *upper_bound;

  Window_frame_bound *lower_bound;

  Frame_exclusion exclusion;

  Window_frame(Frame_units win_frame_units,
               Window_frame_bound *win_frame_upper_bound,
               Window_frame_bound *win_frame_lower_bound,
               Frame_exclusion win_frame_exclusion)
  {
    units= win_frame_units;
    upper_bound= win_frame_upper_bound;
    lower_bound= win_frame_lower_bound;
    exclusion= win_frame_exclusion;
  }

};

class Window_spec : public Sql_alloc
{
 public:

  LEX_STRING *window_ref;

  SQL_I_List<ORDER> partition_list;

  SQL_I_List<ORDER> order_list;

  Window_frame *window_frame;

  Window_spec(LEX_STRING *win_ref, 
              SQL_I_List<ORDER> part_list,
              SQL_I_List<ORDER> ord_list,
              Window_frame *win_frame)
  {
    window_ref= win_ref;
    partition_list= part_list;
    order_list= ord_list;
    window_frame= win_frame;
  }
};

class Window_def : public Window_spec
{
 public:

  LEX_STRING *window_name;

  Window_def(LEX_STRING *win_name,
             LEX_STRING *win_ref, 
             SQL_I_List<ORDER> part_list,
             SQL_I_List<ORDER> ord_list,
             Window_frame *win_frame) 
    :Window_spec(win_ref, part_list, ord_list, win_frame)
  {
    window_name= win_name;
  }

};

#endif /* SQL_WINDOW_INCLUDED */
