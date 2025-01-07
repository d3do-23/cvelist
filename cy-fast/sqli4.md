### BUG_Author:

Wu Wenhao with StarMap Team of Legendsec at QI-ANXIN Group

Yin Lingyun with StarMap Team of Legendsec at QI-ANXIN Group

### Affected version:

cy-fast

### Vendor:

cy-fast

### Software:

https://gitee.com/leiyuxi/cy-fast

### Vulnerability File:

CommparaController.java

### Description:

The current version of cy-fast has an SQL injection vulnerability that allows attackers to execute SQL statements.
Due to the lack of comprehensive filtering of SQL statements, users can concatenate and execute unfiltered SQL functions.



Severity: High



The issue lies in the route `/sys/menu/listData`. Due to insufficient filtering, SQL functions can be executed through concatenation.

Corresponding critical code for handling the issue.

```
    @ResponseBody
    @RequestMapping("/listData")
    @RequiresPermissions("sys:menu:list")
    public R listData(@RequestParam Map<String, Object> params) {
        //查询列表数据
        Query query = new Query(params);
        List<SysMenu> menuList = sysMenuService.queryList(query);
        int total = sysMenuService.queryTotal(query);

        PageUtils pageUtil = new PageUtils(menuList, total, query.getLimit(), query.getPage());

        return R.ok().put("page", pageUtil);
    }
```

```
<when test="sidx != null and sidx.trim() != ''">
    order by ${sidx} ${order}
</when>
```



final poc:

![image-20250107103034039](sqli4.assets/image-20250107103034039.png)

![image-20250107103050475](sqli4.assets/image-20250107103050475.png)