
#include "../basic_fun.h"

#include <map>

using namespace std;


#if 1
    #undef DBG_PRINT
    #undef DBG_SHOW_WSTRING
    #define DBG_PRINT(_x)
    #define DBG_SHOW_WSTRING(_uni)
#endif


//////////////////////////////////////////////////////////////////////////


#define MAX_MD5_TREE_DATA_SIZE (0x100000) // 1MB
#define MD5_TREE_SIGNATUR ((T_Dword)'T5dm')
#define MD5_TREE_VERSION ((T_Dword)1)


//////////////////////////////////////////////////////////////////////////


class Cmd5TreeNode
{
private:
    T_byte m_md5[16];
public:
    friend class Cmd5Tree;
    Cmd5TreeNode(T_byte md5[16])
    {
        memcpy(m_md5,md5,16);
    }
    Cmd5TreeNode(const Cmd5TreeNode& another)
    {
        memcpy(m_md5,another.m_md5,16);
    }
	const Cmd5TreeNode& operator=(const Cmd5TreeNode& another)
	{
		memcpy(m_md5, another.m_md5, 16);
	}
    bool operator<(const Cmd5TreeNode& another) const
    {
        PT_Bit32u l1,l2;
        l1 = (PT_Bit32u)m_md5;
        l2 = (PT_Bit32u)another.m_md5;
        for (T_Dword i=0;i<4;++i)
        {
            if (l1[i] < l2[i])
            {
                return true;
            }
            else if (l1[i] > l2[i])
            {
                return false;
            }
        }
        return false;
    }
    bool operator==(const Cmd5TreeNode& another) const
    {
        PT_Bit32u l1,l2;
        l1 = (PT_Bit32u)m_md5;
        l2 = (PT_Bit32u)another.m_md5;
        for (T_Dword i=0;i<4;++i)
        {
            if (l1[i] != l2[i])
            {
                return false;
            }
        }
        return true;
    }
};

class CdataNode
{
private:
    PT_byte m_data;
    T_Dword m_length;
public:
    friend class Cmd5Tree;
    CdataNode(const void *data,T_Dword length)
    {
		m_data = new T_byte[length + 1];
        m_length = length;
        memcpy(m_data,data,m_length);
    }
    CdataNode(const CdataNode& another)
    {
		m_data = new T_byte[another.m_length + 1];
        m_length = another.m_length;
        memcpy(m_data,another.m_data,m_length);
    }
    ~CdataNode()
    {
        delete [] m_data;
    }
    const CdataNode &operator=(const CdataNode& another)
    {
        delete [] m_data;
		m_data = new T_byte[another.m_length + 1];
        m_length = another.m_length;
        memcpy(m_data,another.m_data,m_length);
        return *this;
    }
    T_status getData(PT_void out,PT_Dword len) const
    {
        if (*len > m_length)
        {
            memcpy(out,m_data,m_length);
            *len = m_length;
            return T_STATUS_SUCCESS;
        }
        *len = m_length;
        return T_STATUS_BUFFER_TOO_SMALL;
    }
};

class Cmd5Tree
{
private:
    map<Cmd5TreeNode,CdataNode> m_map;
    BLPP_QUEUED_LOCK m_lock;
public:
    Cmd5Tree()
    {
        blpp_Lock_InitializeQueuedLock(&m_lock);
    }
    bool insert(const Cmd5TreeNode &md5,const CdataNode &data)
    {
        AutoQueuedLock al(m_lock,true);
        pair<map<Cmd5TreeNode,CdataNode>::iterator,bool> ret = m_map.insert(pair<Cmd5TreeNode,CdataNode>(md5,data));
        return ret.second;
    }
    void erase(const Cmd5TreeNode &md5)
    {
        AutoQueuedLock al(m_lock,true);
        m_map.erase(md5);
    }
    T_status find(const Cmd5TreeNode &md5,PT_void dataOut,PT_Dword outLength)
    {
        AutoQueuedLock al(m_lock);
        map<Cmd5TreeNode,CdataNode>::const_iterator it = m_map.find(md5);
        if (it != m_map.end())
        {
            return it->second.getData(dataOut,outLength);
        }
        return T_STATUS_NOT_FOUND;
    }
    void clear()
    {
        AutoQueuedLock al(m_lock,true);
        m_map.clear();
    }
    bool save(HANDLE hFile)
    {
        AutoQueuedLock al(m_lock);
        DWORD re;
        for (map<Cmd5TreeNode,CdataNode>::const_iterator it=m_map.begin();it!=m_map.end();++it)
        {
            //
            // First MD5
            // Second DataLength
            // Third Data
            //
            if (!WriteFile(hFile,it->first.m_md5,16,&re,NULL) || re!=16)
            {
                return false;
            }
            T_Dword DataLength = it->second.m_length;
            if (!WriteFile(hFile,&DataLength,sizeof(T_Dword),&re,NULL) || re!=sizeof(T_Dword))
            {
                return false;
            }
			if (!WriteFile(hFile, it->second.m_data, DataLength, &re, NULL) || re != DataLength)
            {
                return false;
            }
        }
        return true;
    }
    bool load(HANDLE hFile)
    {
        AutoQueuedLock al(m_lock,true);
        DWORD re;
        while (true)
        {
            T_byte md5[16];
            if (!ReadFile(hFile,md5,16,&re,NULL) || re!=16)
            {
				if (0 == re)
				{
					return true;
				}
				return false;
            }
            T_Dword DataLength;
            if (!ReadFile(hFile,&DataLength,sizeof(T_Dword),&re,NULL) || re!=sizeof(T_Dword))
            {
                return false;
            }
            if (DataLength > MAX_MD5_TREE_DATA_SIZE)
            {
                return false;
            }
            PT_byte data = (PT_byte)blpp_mem_alloc(DataLength);
            if (NULL == data)
            {
                return false;
            }
            if (!ReadFile(hFile,data,DataLength,&re,NULL) || re!=DataLength)
            {
                blpp_mem_free(data);
                return false;
            }
            m_map.insert(pair<Cmd5TreeNode,CdataNode>(Cmd5TreeNode(md5),CdataNode(data,DataLength)));
            blpp_mem_free(data);
        }
    }
};

PT_void blpp_md5Tree_New()
{
    return new Cmd5Tree;
}

T_void blpp_md5Tree_Delete(PT_void tree)
{
    if (tree)
    {
        delete ((Cmd5Tree *)tree);
    }
}

T_status blpp_md5Tree_Insert(PT_void tree,T_byte md5[16],PCT_void data,T_Dword length)
{
    if (NULL==tree || NULL==data || length>MAX_MD5_TREE_DATA_SIZE)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    Cmd5Tree *md5Tree = (Cmd5Tree *)tree;
    if (!md5Tree->insert(Cmd5TreeNode(md5),CdataNode(data,length)))
    {
        return T_STATUS_ALREADY_EXISTS;
    }
    return T_STATUS_SUCCESS;
}

T_status blpp_md5Tree_Erase(PT_void tree,T_byte md5[16])
{
    if (NULL == tree)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    Cmd5Tree *md5Tree = (Cmd5Tree *)tree;
    md5Tree->erase(Cmd5TreeNode(md5));
    return T_STATUS_SUCCESS;
}

T_status blpp_md5Tree_Find(PT_void tree,T_byte md5[16],PT_void dataOut,PT_Dword dataLength)
{
    if (NULL==tree || NULL==dataOut || NULL==dataLength)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    Cmd5Tree *md5Tree = (Cmd5Tree *)tree;
    return md5Tree->find(Cmd5TreeNode(md5),dataOut,dataLength);
}

T_status blpp_md5Tree_Clear(PT_void tree)
{
    if (NULL == tree)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    Cmd5Tree *md5Tree = (Cmd5Tree *)tree;
    md5Tree->clear();
    return T_STATUS_SUCCESS;
}

static T_status internalLoad(Cmd5Tree *md5Tree,HANDLE hFile)
{
    //
    // First SIGN
    // Second VERSION
    // Third DataList
    //
    T_Dword tmpDw;
    DWORD re;
    if (!ReadFile(hFile,&tmpDw,sizeof(T_Dword),&re,NULL) || re!=sizeof(T_Dword))
    {
        return T_STATUS_ACCESS_DENIED;
    }
    if (tmpDw != MD5_TREE_SIGNATUR)
    {
        return T_STATUS_EXCLUDE;
    }
    if (!ReadFile(hFile,&tmpDw,sizeof(T_Dword),&re,NULL) || re!=sizeof(T_Dword))
    {
        return T_STATUS_ACCESS_DENIED;
    }
    if (tmpDw != MD5_TREE_VERSION)
    {
        return T_STATUS_EXCLUDE;
    }
    return md5Tree->load(hFile)?T_STATUS_SUCCESS:T_STATUS_UNKOWN_ERROR;
}

T_status blpp_md5Tree_LoadA(PT_void tree,PCT_str dbPath)
{
    if (NULL==tree || NULL==dbPath)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    Cmd5Tree *md5Tree = (Cmd5Tree *)tree;
    HANDLE hFile = CreateFileA(dbPath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        return T_STATUS_NOT_FOUND;
    }
    T_status status = internalLoad(md5Tree,hFile);
    CloseHandle(hFile);
    return status;
}

T_status blpp_md5Tree_LoadW(PT_void tree,PCT_wstr dbPath)
{
    if (NULL==tree || NULL==dbPath)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    Cmd5Tree *md5Tree = (Cmd5Tree *)tree;
    HANDLE hFile = CreateFileW(dbPath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        return T_STATUS_NOT_FOUND;
    }
    T_status status = internalLoad(md5Tree,hFile);
    CloseHandle(hFile);
    return status;
}

static T_status internalSave(Cmd5Tree *md5Tree,HANDLE hFile)
{
    //
    // First SIGN
    // Second VERSION
    // Third DataList
    //
    T_Dword tmpDw;
    DWORD re;
    tmpDw = MD5_TREE_SIGNATUR;
    if (!WriteFile(hFile,&tmpDw,sizeof(T_Dword),&re,NULL) || re!=sizeof(T_Dword))
    {
        return T_STATUS_ACCESS_DENIED;
    }
    tmpDw = MD5_TREE_VERSION;
    if (!WriteFile(hFile,&tmpDw,sizeof(T_Dword),&re,NULL) || re!=sizeof(T_Dword))
    {
        return T_STATUS_ACCESS_DENIED;
    }
    return md5Tree->save(hFile)?T_STATUS_SUCCESS:T_STATUS_UNKOWN_ERROR;
}

T_status blpp_md5Tree_SaveA(PT_void tree,PCT_str dbPath)
{
    if (NULL==tree || NULL==dbPath)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    Cmd5Tree *md5Tree = (Cmd5Tree *)tree;
    HANDLE hFile = CreateFileA(dbPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        return T_STATUS_NOT_FOUND;
    }
    T_status status = internalSave(md5Tree,hFile);
    CloseHandle(hFile);
    return status;
}

T_status blpp_md5Tree_SaveW(PT_void tree,PCT_wstr dbPath)
{
    if (NULL==tree || NULL==dbPath)
    {
        return T_STATUS_INVALID_PARAMETER;
    }
    Cmd5Tree *md5Tree = (Cmd5Tree *)tree;
    HANDLE hFile = CreateFileW(dbPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        return T_STATUS_NOT_FOUND;
    }
    T_status status = internalSave(md5Tree,hFile);
    CloseHandle(hFile);
    return status;
}
