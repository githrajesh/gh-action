import java
import semmle.code.java.security.XssQuery
import XzzFlow

from XssFlow::PathNode source, XssFlow::PathNode sink
where XssFlow::flowPath(source, sink)
select sink.getNode() source, sink "Cross site scripting vul. detected"
source.getNode(), "User Provide Value"
