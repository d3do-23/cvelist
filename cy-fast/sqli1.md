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

SysRoleController.java

### Description:

The current version of cy-fast has an SQL injection vulnerability that allows attackers to execute SQL statements.
Due to the lack of comprehensive filtering of SQL statements, users can concatenate and execute unfiltered SQL functions.



Severity: High



The issue lies in the route `/sys/role/listData`. Due to insufficient filtering, SQL functions can be executed through concatenation.

Corresponding critical code for handling the issue.

```
@ResponseBody
@RequestMapping("/listData")
@RequiresPermissions("sys:role:list")
public R listData(@RequestParam Map<String, Object> params) {
    //如果不是超级管理员，则只查询自己创建的角色列表
    if (getUserId() != Constant.SUPER_ADMIN) {
        params.put("createUserId", getUserId());
    }

    //查询列表数据
    Query query = new Query(params);
    List<SysRole> list = sysRoleService.queryList(query);
    int total = sysRoleService.queryTotal(query);

    PageUtils pageUtil = new PageUtils(list, total, query.getLimit(), query.getPage());

    return R.ok().put("page", pageUtil);
}
```

```
<when test="sidx != null and sidx.trim() != ''">
    order by ${sidx} ${order}
</when>
```



final poc:

![image-20250106171234465](/mnt/08B1AFFA3DEB5523/alinuxfiles/cvelist/cy-fast/sqli1.assets/image-20250106171234465.png)