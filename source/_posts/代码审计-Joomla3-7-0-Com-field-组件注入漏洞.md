---
title: 代码审计-Joomla3.7.0_Com_field_组件注入漏洞
date: 2019-02-11 01:37:32
tags:
    - web安全
    - 代码审计
---

Joomla!是一套全球知名的内容管理系统。Joomla!是使用PHP语言加上MySQL数据库所开发的软件系统，可以在Linux、 Windows、MacOSX等各种不同的平台上执行。目前是由Open Source Matters（见扩展阅读）这个开放源码组织进行开发与支持，这个组织的成员来自全世界各地，小组成员约有150人，包含了开发者、设计者、系统管理者、文件撰写者，以及超过2万名的参与会员。

## 漏洞简述

这个漏洞出现在Joomla3.7.0新增的组件com_field里，这个组件的访问没有做任何身份验证，并且在处理fullordering参数时没有合格的过滤，导致最终将用户的输入拼接在了sql查询语句的order by参数里，形成注入。

## 源码结构

Joomla!源码结构如下图  
![](/img/joomla/1.png)

## 调用流程

入口函数如下，前面的都是用来宏定义一些参数，最后一行execute转入site.php接着转入helper.php，通过require_once调用传入的组件参数。

![](/img/joomla/2.png)

如下为Joomla的调用栈,可以很清晰的看到Joomla的调用路径。

![](/img/joomla/3.png)

这个fields.php关键代码如下。分别完成了组件注册，控制器的实例生成，执行命令等功能。

```
JLoader::register('FieldsHelper', JPATH_ADMINISTRATOR . '/components/com_fields/helpers/fields.php');
$controller = JControllerLegacy::getInstance('Fields');
$controller->execute(JFactory::getApplication()->input->get('task'));
$controller->redirect();
```


首先来看看fields组件生成实例部分的代码，在它的构造函数里，注意到当我们访问这个组件时，它会把路径设置为JPATH_COMPONENT_ADMINISTRATOR,而这个宏定义默认为administrator\\components\\，使得后面加载model时是直接用administrator目录下的函数进行加载。

```
public function __construct($config = array())
{
    $this->input = JFactory::getApplication()->input;
    // Frontpage Editor Fields Button proxying:
    if ($this->input->get('view') === 'fields' && $this->input->get('layout') === 'modal')
    {
        // Load the backend language file.
        $lang = JFactory::getLanguage();
        $lang->load('com_fields', JPATH_ADMINISTRATOR);
        $config['base_path'] = JPATH_COMPONENT_ADMINISTRATOR;
    }
    parent::__construct($config);
}
```


在获取实例后就进入了$controller->execute方法，该方法首先调用如下函数，它最后返回的doTask值为display,接着调用库函数中的display函数，它又会调用组件目录下display函数。



```
public function execute($task)
    {
        $this->task = $task;
        $task = strtolower($task);
        if (isset($this->taskMap[$task]))
        {
            $doTask = $this->taskMap[$task];
        }
        elseif (isset($this->taskMap['__default']))
        {
            $doTask = $this->taskMap['__default'];
        }
        else
        {
            throw new Exception(JText::sprintf('JLIB_APPLICATION_ERROR_TASK_NOT_FOUND', $task), 404);
        }
        // Record the actual task being fired
        $this->doTask = $doTask;
        return $this->$doTask();
    }
```

 |

display函数调用组件的model文件，接着它调用了libraries\\legacy\\model\\list.php中的populateState方法，在处理参数fulloredering时，没有太多严格的过滤，接着就直接使用了setstate方法把用户输入保存了下来。


```
case 'fullordering':
    $orderingParts = explode(' ', $value);
    if (count($orderingParts) >= 2)
    {
        ...
    }
    else
    {
        $this->setState('list.ordering', $ordering);
        $this->setState('list.direction', $direction);
    }
    break;
    ...
$value = $app->getUserStateFromRequest($this->context . '.limitstart', 'limitstart', 0, 'int');
$limitstart = ($limit != 0 ? (floor($value / $limit) * $limit) : 0);
$this->setState('list.start', $limitstart);
```

 |

保存下来的用户输入如下。

![](/img/joomla/4.png)

整个调用栈如下

![](/img/joomla/5.png)

其中调用getUserStateFromRequest方法处理用户的输入，接着它调用了getUserState方法进行处理，注册session,生成list.fullordering的值。

```
public function getUserState($key, $default = null)
{
    $session = JFactory::getSession();
    $registry = $session->get('registry');
    if (!is_null($registry))
    {
        return $registry->get($key, $default);
    }
    return $default;
}
```

 |

接着在display函数里的$this->get(Items’)方法中，通过getstate方法将list.fullordering的值，在逃脱了escape方法过滤的情况下，拼接进了sql语句中，并在之后得到执行并回显

```
// Add the list ordering clause
$listOrdering = $this->getState('list.fullordering', 'a.ordering');
$orderDirn    = '';
if (empty($listOrdering))
{
    $listOrdering  = $this->state->get('list.ordering', 'a.ordering');
    $orderDirn     = $this->state->get('list.direction', 'DESC');
}
    
$query->order($db->escape($listOrdering) . ' ' . $db->escape($orderDirn));  
return $query;
```

执行结果如下

![](/img/joomla/6.png)

流程图如下

![](/img/joomla/7.png)

## 修复方法

官方给出的修复如下

![](/img/joomla/8.png)

在第三步拼接sql时，在administrator/components/com_fields/models/fields.php里不再使用用户可控的fullordering参数，而是直接拼接ordering参数，而这个参数在输入时会进行白名单检测，无法形成注入，因此可以成功防御此漏洞。




