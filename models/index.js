import fs from "fs/promises";
import { nanoid } from "nanoid";
import path from "path";

const contactsPath = path.resolve("models", "contacts.json");
const updateContacts = contacts => fs.writeFile(contactsPath, JSON.stringify(contacts, null, 2));

//  Повертає масив контактів.
const listContacts = async () => {
    const result = await fs.readFile(contactsPath);
    return JSON.parse(result);
  }
  
//  Повертає об'єкт контакту з таким id. Повертає null, якщо контакт з таким id не знайдений.  
const getContactById = async (contactId) => {
    const contacts = await listContacts();
    const result = contacts.find(item => item.id === contactId);
    return result || null;
  }

//  Повертає об'єкт доданого контакту. 
const addContact = async({name, email, phone}) => {
  const contacts = await listContacts();
  const newContact = {
    id: nanoid(),
    name,
    email,
    phone
  }

  contacts.push(newContact);
  await updateContacts(contacts);
  return newContact;
  }
  
  //  Оновлює контакт, повертає оновлений об'єкт контакту
  export const updateContactById = async (contactId, data) => {
    const contacts = await listContacts();
    const index = contacts.findIndex(item => item.id === contactId);
    if (index === -1) {
        return null;
    }
    contacts[index] = { ...contacts[index], ...data };
    await updateContacts(contacts);
    return contacts[index];
}

  //  Повертає об'єкт видаленого контакту. Повертає null, якщо контакт з таким id не знайдений. 
const removeContact = async(contactId) => {
  const contacts = await listContacts();
  const index = contacts.findIndex(item => item.id === contactId);
  if(index === -1) {
      return null
  }

  const [result] = contacts.splice(index, 1);
  await updateContacts(contacts);
  return result;
}

  export default {
    listContacts,
    getContactById,
    removeContact,
    addContact,
    updateContactById,
  }
