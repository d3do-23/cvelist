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



The issue lies in the route `/commpara/listData`. Due to insufficient filtering, SQL functions can be executed through concatenation.

Corresponding critical code for handling the issue.

```
    @ResponseBody
	@RequestMapping("/listData")
	@RequiresPermissions("commpara:list")
	public R listData(@RequestParam Map<String, Object> params){
		//查询列表数据
        Query query = new Query(params);

		List<Commpara> commparaList = commparaService.queryList(query);
		int total = commparaService.queryTotal(query);
		
		PageUtils pageUtil = new PageUtils(commparaList, total, query.getLimit(), query.getPage());
		
		return R.ok().put("page", pageUtil);
	}
```

```
<when test="sidx != null and sidx.trim() != ''">
    order by ${sidx} ${order}
</when>
```



final poc:

![image-20250107095055678](sqli3.assets/image-20250107095055678.png)

![image-20250107095117665](sqli3.assets/image-20250107095117665.png)