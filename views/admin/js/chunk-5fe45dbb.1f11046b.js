(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-5fe45dbb"],{"0648":function(t,a,e){"use strict";var n=e("9369"),u=e.n(n);u.a},9369:function(t,a,e){},a55b:function(t,a,e){"use strict";e.r(a);var n=function(){var t=this,a=t.$createElement,e=t._self._c||a;return e("div",{staticClass:"login"},[e("at-card",{staticClass:"card",staticStyle:{width:"300px"},attrs:{bordered:!1}},[e("h4",{staticClass:"title",attrs:{slot:"title"},slot:"title"},[t._v("登录")]),e("div",[e("at-input",{staticClass:"input",attrs:{placeholder:"用户名",status:"",icon:""},model:{value:t.inputValue1,callback:function(a){t.inputValue1=a},expression:"inputValue1"}}),e("at-input",{attrs:{type:"password",placeholder:"密码",status:"",icon:""},model:{value:t.inputValue2,callback:function(a){t.inputValue2=a},expression:"inputValue2"}})],1),e("div",{staticClass:"btn"},[e("at-button",{attrs:{type:"primary"},on:{click:t.doLogin}},[t._v("登录")])],1)])],1)},u=[],o=e("5f87"),i={components:{},data:function(){return{inputValue1:"",inputValue2:""}},computed:{},watch:{},beforeRouteEnter:function(t,a,e){Object(o["a"])()?e("/"):e()},methods:{doLogin:function(){var t=this;this.$http({method:"post",url:"https://account.api.mcloc.cn/login",data:{username:this.inputValue1,password:this.inputValue2}}).then((function(a){2e4===a.data.code&&(Object(o["e"])(a.data.data.token),Object(o["f"])(a.data.data.uuid),t.$Message.success(a.data.msg),t.$router.push({path:"/home"})),40001===a.data.code&&t.$Message.error(a.data.msg)}))}},created:function(){},mounted:function(){},beforeCreate:function(){},beforeMount:function(){},beforeUpdate:function(){},updated:function(){},beforeUnmount:function(){},unmounted:function(){},activated:function(){}},c=i,s=(e("0648"),e("2877")),l=Object(s["a"])(c,n,u,!1,null,"68ecf90c",null);a["default"]=l.exports}}]);