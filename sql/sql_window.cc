#include "sql_select.h"
#include "sql_window.h"

int
setup_windows(THD *thd, Item **ref_pointer_array, TABLE_LIST *tables,
	      List<Item> &fields, List<Item> &all_fields, 
              List<Window_spec> win_specs)
{
  int res= 0;
  Window_spec *win_spec;
  DBUG_ENTER("setup_windows");
  List_iterator<Window_spec> it(win_specs);
  while ((win_spec= it++))
  {
    bool hidden_group_fields;
    res= setup_group(thd, ref_pointer_array, tables, fields, all_fields,
                     win_spec->partition_list.first, &hidden_group_fields);
    res= res || setup_order(thd, ref_pointer_array, tables, fields, all_fields,
                            win_spec->order_list.first);
  }
  DBUG_RETURN(res);
}
