'use strict';
function fields(value,allowed,required=[]){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!allowed.includes(k))||required.some(k=>!Object.hasOwn(value,k)))throw Error('invalid runtime fields');
}
module.exports={fields};
